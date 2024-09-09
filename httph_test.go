package httph_test

import (
	_ "embed"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maragudk/is"

	"maragu.dev/httph"
)

type validatedFormReq struct{}

func (r validatedFormReq) Validate() error {
	return errors.New("invalid")
}

func TestFormHandler(t *testing.T) {
	t.Run("parses a form into a struct", func(t *testing.T) {
		type formReq struct {
			Name    string
			Age     int
			Accept  bool
			Hobbies []string
		}

		h := httph.FormHandler(func(w http.ResponseWriter, r *http.Request, req formReq) {
			is.Equal(t, "Me", req.Name)
			is.Equal(t, 20, req.Age)
			is.Equal(t, true, req.Accept)
			is.Equal(t, 2, len(req.Hobbies))
			is.Equal(t, "Hats", req.Hobbies[0])
			is.Equal(t, "Goats", req.Hobbies[1])
			http.Redirect(w, r, "/", http.StatusFound)
		})

		vs := url.Values{}
		vs.Set("name", "Me")
		vs.Set("age", "20")
		vs.Set("accept", "true")
		vs.Add("hobbies", "Hats")
		vs.Add("hobbies", "Goats")
		req := createFormRequest(vs)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusFound, res.Result().StatusCode)
	})

	t.Run("returns bad request on bad input values", func(t *testing.T) {
		type formReq struct {
			Age int
		}

		h := httph.FormHandler(func(w http.ResponseWriter, r *http.Request, req formReq) {})

		vs := url.Values{}
		vs.Set("age", "not a number")
		req := createFormRequest(vs)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.True(t, strings.Contains(readBody(t, res.Result().Body), "cannot parse 'Age' as int"))
	})

	t.Run("returns bad request when Validate() returns error", func(t *testing.T) {
		h := httph.FormHandler(func(w http.ResponseWriter, r *http.Request, req validatedFormReq) {})

		vs := url.Values{}
		vs.Set("name", "")
		req := createFormRequest(vs)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.Equal(t, "invalid form: invalid", readBody(t, res.Result().Body))
	})
}

func createFormRequest(vs url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(vs.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func readBody(t *testing.T, r io.Reader) string {
	d, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(d))
}

func TestNoClickjacking(t *testing.T) {
	t.Run("adds X-Frame-Options and X-XSS-Protection headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h := httph.NoClickjacking(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "deny", res.Result().Header.Get("X-Frame-Options"))
		is.Equal(t, "1; mode=block", res.Result().Header.Get("X-XSS-Protection"))
	})
}

func TestContentSecurityPolicy(t *testing.T) {
	t.Run("restrict everything to 'none' except images, styles, scripts, and fonts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h := httph.ContentSecurityPolicy(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'",
			res.Result().Header.Get("Content-Security-Policy"))
	})

	t.Run("can set directives with options function", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		optsFunc := func(opts *httph.ContentSecurityPolicyOptions) {
			opts.DefaultSrc = "https:"
			opts.FontSrc = ""
			opts.ScriptSrc = ""
		}
		h := httph.ContentSecurityPolicy(optsFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "default-src https:; img-src 'self'; style-src 'self'",
			res.Result().Header.Get("Content-Security-Policy"))
	})
}

//go:embed testdata/goget.html
var goGetHTML string

func TestGoGet(t *testing.T) {
	t.Run("serves HTML for Go modules", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/httph?go-get=1", nil)
		res := httptest.NewRecorder()

		h := httph.GoGet(httph.GoGetOptions{
			Domain:    "maragu.dev",
			Modules:   []string{"httph"},
			URLPrefix: "https://github.com/maragudk",
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})
		h(next).ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, goGetHTML, res.Body.String())
		is.True(t, !called)
	})

	t.Run("passes through non-module requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h := httph.GoGet(httph.GoGetOptions{
			Domain:    "maragu.dev",
			Modules:   []string{"httph"},
			URLPrefix: "https://github.com/maragudk",
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})
		h(next).ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.True(t, called)
	})

	t.Run("redirects valid modules to the URL prefix when no go-get parameter is supplied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/httph", nil)
		res := httptest.NewRecorder()

		h := httph.GoGet(httph.GoGetOptions{
			Domain:    "maragu.dev",
			Modules:   []string{"httph"},
			URLPrefix: "https://github.com/maragudk",
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})
		h(next).ServeHTTP(res, req)

		is.Equal(t, http.StatusPermanentRedirect, res.Result().StatusCode)
		is.True(t, !called)
	})
}

func TestVersionedAssets(t *testing.T) {
	t.Run("removes version from asset path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/script.123456.js", nil)
		res := httptest.NewRecorder()

		h := httph.VersionedAssets(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "/script.js", req.URL.Path)
	})

	t.Run("does not modify path without version", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/script.js", nil)
		res := httptest.NewRecorder()

		h := httph.VersionedAssets(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "/script.js", req.URL.Path)
	})
}
