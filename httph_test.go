package httph_test

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"maragu.dev/httph"
	"maragu.dev/is"
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
		is.True(t, strings.Contains(readBody(t, res), "cannot parse 'Age' as int"))
	})

	t.Run("returns bad request when Validate() returns error", func(t *testing.T) {
		h := httph.FormHandler(func(w http.ResponseWriter, r *http.Request, req validatedFormReq) {})

		vs := url.Values{}
		vs.Set("name", "")
		req := createFormRequest(vs)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.Equal(t, "invalid form: invalid", readBody(t, res))
	})
}

func ExampleFormHandler() {
	type Req struct {
		Name string
		Age  int
	}

	h := httph.FormHandler(func(w http.ResponseWriter, r *http.Request, req Req) {
		_, _ = fmt.Fprintf(w, "Hello %v, you are %v years old", req.Name, req.Age)
	})

	w := httptest.NewRecorder()
	vs := url.Values{
		"name": {"World"},
		"age":  {"20"},
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(vs.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(w, r)

	body, _ := io.ReadAll(w.Result().Body)
	fmt.Println(string(body))
	//Output: Hello World, you are 20 years old
}

func createFormRequest(vs url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(vs.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func readBody(t *testing.T, r *httptest.ResponseRecorder) string {
	t.Helper()

	d, err := io.ReadAll(r.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(d))
}

type jsonRes struct {
	Message string
}

func (j jsonRes) StatusCode() int {
	return http.StatusAccepted
}

type tinyJSONReq struct {
	Name string
}

func (t tinyJSONReq) MaxSizeBytes() int64 {
	return 1
}

type validatedJSONReq struct {
	Name string
}

func (v validatedJSONReq) Validate() error {
	if v.Name == "" {
		return errors.New("name cannot be empty")
	}
	return nil
}

func TestJSONHandler(t *testing.T) {
	t.Run("encodes response body to JSON", func(t *testing.T) {
		type jsonRes struct {
			Message string `json:"message"`
		}

		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, _ any) (jsonRes, error) {
			return jsonRes{Message: "Yo"}, nil
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, `{"message":"Yo"}`, readBody(t, res))
	})

	t.Run("parses request body from JSON", func(t *testing.T) {
		type jsonReq struct {
			Name string
		}

		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, req jsonReq) (any, error) {
			is.Equal(t, "Me", req.Name)
			return nil, nil
		})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Name":"Me"}`))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
	})

	t.Run("returns bad request if request body is not valid JSON", func(t *testing.T) {
		type jsonReq struct {
			Name string
		}

		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, req jsonReq) (any, error) {
			return nil, nil
		})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{`))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.Equal(t, `{"Error":"error decoding request body as JSON: unexpected EOF"}`, readBody(t, res))
	})

	t.Run("returns error message if handler errors", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, _ any) (any, error) {
			return nil, errors.New("oh no")
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusInternalServerError, res.Result().StatusCode)
		is.Equal(t, `{"Error":"oh no"}`, readBody(t, res))
	})

	t.Run("returns error message with custom http status code if error satisfies statusCodeGiver", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, _ any) (any, error) {
			return nil, httph.HTTPError{Code: http.StatusTeapot}
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusTeapot, res.Result().StatusCode)
		is.Equal(t, `{"Error":"I'm a teapot"}`, readBody(t, res))
	})

	t.Run("returns error message if response body cannot be encoded to JSON", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, _ any) (any, error) {
			return make(chan int), nil
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusInternalServerError, res.Result().StatusCode)
		is.Equal(t, `{"Error":"error encoding response body as JSON: json: unsupported type: chan int"}`, readBody(t, res))
	})

	t.Run("returns custom status code if response struct satisfies statusCodeGiver", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, _ any) (jsonRes, error) {
			return jsonRes{Message: "Yo"}, nil
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusAccepted, res.Result().StatusCode)
		is.Equal(t, `{"Message":"Yo"}`, readBody(t, res))
	})

	t.Run("returns bad request if request body is too large", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, _ tinyJSONReq) (any, error) {
			return nil, nil
		})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Name":"Me"}`))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.Equal(t, `{"Error":"error decoding request body as JSON: http: request body too large"}`, readBody(t, res))
	})

	t.Run("returns bad request if request body fails validation", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, req validatedJSONReq) (any, error) {
			return nil, nil
		})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Name":""}`))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.Equal(t, `{"Error":"invalid request body: name cannot be empty"}`, readBody(t, res))
	})

	t.Run("returns bad request if request body should be validated but is not present", func(t *testing.T) {
		h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, req validatedJSONReq) (any, error) {
			return nil, nil
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusBadRequest, res.Result().StatusCode)
		is.Equal(t, `{"Error":"invalid request body: name cannot be empty"}`, readBody(t, res))
	})
}

func ExampleJSONHandler() {
	type Req struct {
		Name string
	}

	type Res struct {
		Message string
	}

	h := httph.JSONHandler(func(w http.ResponseWriter, r *http.Request, req Req) (Res, error) {
		return Res{Message: "Hello " + req.Name}, nil
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Name":"World"}`)))

	body, _ := io.ReadAll(w.Result().Body)
	fmt.Println(string(body))
	//Output: {"Message":"Hello World"}
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
	t.Run("restrict everything to 'none' except connect, images, styles, scripts, manifest, and fonts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h := httph.ContentSecurityPolicy(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self'",
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
		is.Equal(t, "default-src https:; connect-src 'self'; img-src 'self'; manifest-src 'self'; style-src 'self'",
			res.Result().Header.Get("Content-Security-Policy"))
	})

	t.Run("appends a nonce to script-src with ScriptNonce", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
		})

		is.True(t, nonce != "")
		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self' 'nonce-%v'; style-src 'self'", nonce), v)
	})

	t.Run("appends a nonce to style-src with StyleNonce", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.StyleNonce = true
		})

		is.True(t, nonce != "")
		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self' 'nonce-%v'", nonce), v)
	})

	t.Run("appends the same nonce to both script-src and style-src", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
			opts.StyleNonce = true
		})

		is.True(t, nonce != "")
		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self' 'nonce-%v'; style-src 'self' 'nonce-%v'", nonce, nonce), v)
	})

	t.Run("does not generate a nonce by default", func(t *testing.T) {
		v, nonce := serveWithCSP(t, nil)

		is.Equal(t, "", nonce)
		is.Equal(t, "default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self'", v)
	})

	t.Run("generates a different nonce for each request through the same handler", func(t *testing.T) {
		var nonces, headers []string

		h := httph.ContentSecurityPolicy(func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonces = append(nonces, httph.NonceFromContext(r.Context()))
		}))

		for range 2 {
			res := httptest.NewRecorder()
			h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))
			headers = append(headers, res.Result().Header.Get("Content-Security-Policy"))
		}

		is.True(t, nonces[0] != nonces[1])
		for i, nonce := range nonces {
			is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self' 'nonce-%v'; style-src 'self'", nonce), headers[i])
		}
	})

	t.Run("generates a long nonce with characters safe for the header", func(t *testing.T) {
		_, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
		})

		is.True(t, len(nonce) >= 26)
		is.True(t, regexp.MustCompile(`^[A-Za-z0-9+/\-_]+=*$`).MatchString(nonce))
	})

	t.Run("sets script-src to just the nonce if its value is empty", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptSrc = ""
			opts.ScriptNonce = true
		})

		is.True(t, nonce != "")
		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'nonce-%v'; style-src 'self'", nonce), v)
	})

	t.Run("sets style-src to just the nonce if its value is empty", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.StyleSrc = ""
			opts.StyleNonce = true
		})

		is.True(t, nonce != "")
		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'nonce-%v'", nonce), v)
	})

	t.Run("adds the nonce to script-src-elem and style-src-elem if they're not empty", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptSrcElem = "'self'"
			opts.ScriptNonce = true
			opts.StyleSrcElem = "'self'"
			opts.StyleNonce = true
		})

		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self' 'nonce-%v'; script-src-elem 'self' 'nonce-%v'; style-src 'self' 'nonce-%v'; style-src-elem 'self' 'nonce-%v'", nonce, nonce, nonce, nonce), v)
	})

	t.Run("does not create script-src-elem and style-src-elem if they're empty", func(t *testing.T) {
		v, nonce := serveWithCSP(t, func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
			opts.StyleNonce = true
		})

		is.True(t, !strings.Contains(v, "script-src-elem"))
		is.True(t, !strings.Contains(v, "style-src-elem"))
		is.True(t, strings.Contains(v, fmt.Sprintf("script-src 'self' 'nonce-%v';", nonce)))
	})

	t.Run("shadows the nonce from an outer instance if no nonce is enabled", func(t *testing.T) {
		var nonce string

		inner := httph.ContentSecurityPolicy(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce = httph.NonceFromContext(r.Context())
		}))

		h := httph.ContentSecurityPolicy(func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
		})(inner)

		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))

		is.Equal(t, "", nonce)
		is.Equal(t, "default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self'",
			res.Result().Header.Get("Content-Security-Policy"))
	})

	t.Run("gives an inner instance its own nonce, matching its own header", func(t *testing.T) {
		var outerNonce, innerNonce string

		optsFunc := func(opts *httph.ContentSecurityPolicyOptions) {
			opts.ScriptNonce = true
		}

		inner := httph.ContentSecurityPolicy(optsFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			innerNonce = httph.NonceFromContext(r.Context())
		}))

		h := httph.ContentSecurityPolicy(optsFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			outerNonce = httph.NonceFromContext(r.Context())
			inner.ServeHTTP(w, r)
		}))

		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))

		is.True(t, innerNonce != "")
		is.True(t, innerNonce != outerNonce)
		is.Equal(t, fmt.Sprintf("default-src 'none'; connect-src 'self'; font-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self' 'nonce-%v'; style-src 'self'", innerNonce),
			res.Result().Header.Get("Content-Security-Policy"))
	})
}

// serveWithCSP calls the ContentSecurityPolicy Middleware with the given options function,
// returning the Content-Security-Policy header value and the nonce seen by the inner handler.
func serveWithCSP(t *testing.T, optsFunc func(opts *httph.ContentSecurityPolicyOptions)) (header, nonce string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	h := httph.ContentSecurityPolicy(optsFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce = httph.NonceFromContext(r.Context())
	}))
	h.ServeHTTP(res, req)

	is.Equal(t, http.StatusOK, res.Result().StatusCode)

	return res.Result().Header.Get("Content-Security-Policy"), nonce
}

func TestNonceFromContext(t *testing.T) {
	t.Run("returns the empty string if there is no nonce in the context", func(t *testing.T) {
		is.Equal(t, "", httph.NonceFromContext(t.Context()))
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

func TestErrorHandler(t *testing.T) {
	t.Run("returns no error when handler returns nil", func(t *testing.T) {
		h := httph.ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusAccepted, res.Result().StatusCode)
		is.Equal(t, "success", readBody(t, res))
	})

	t.Run("returns error message with HTTP 500 when handler returns error", func(t *testing.T) {
		h := httph.ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
			return errors.New("something went wrong")
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusInternalServerError, res.Result().StatusCode)
		is.Equal(t, "something went wrong", readBody(t, res))
	})

	t.Run("returns error message with custom status code when error implements statusCodeGiver", func(t *testing.T) {
		h := httph.ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
			return httph.HTTPError{Code: http.StatusTeapot}
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		is.Equal(t, http.StatusTeapot, res.Result().StatusCode)
		is.Equal(t, "I'm a teapot", readBody(t, res))
	})
}

func ExampleErrorHandler() {
	h := httph.ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
		return httph.HTTPError{Code: http.StatusTeapot}
	})

	// Error case
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	body, _ := io.ReadAll(w.Result().Body)
	fmt.Println(string(body))
	//Output: I'm a teapot
}

type customError struct {
	Reason string
}

func (e *customError) Error() string {
	return e.Reason
}

func TestHTTPError(t *testing.T) {
	t.Run("errors.Is finds the wrapped error", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
		}{
			{name: "directly wrapped", err: context.Canceled},
			{name: "further wrapped", err: fmt.Errorf("error doing thing: %w", context.Canceled)},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				err := httph.HTTPError{Code: http.StatusBadRequest, Err: test.err}

				is.True(t, errors.Is(err, context.Canceled))
				is.True(t, !errors.Is(err, context.DeadlineExceeded))
			})
		}
	})

	t.Run("errors.Is finds the wrapped error when the HTTPError is itself wrapped", func(t *testing.T) {
		err := fmt.Errorf("error handling request: %w", httph.HTTPError{Code: http.StatusBadRequest, Err: context.Canceled})

		is.True(t, errors.Is(err, context.Canceled))
	})

	t.Run("errors.As reaches a wrapped custom error type", func(t *testing.T) {
		err := httph.HTTPError{
			Code: http.StatusBadRequest,
			Err:  fmt.Errorf("error doing thing: %w", &customError{Reason: "nope"}),
		}

		var target *customError
		is.True(t, errors.As(err, &target))
		is.Equal(t, "nope", target.Reason)
	})

	t.Run("errors.As still finds the HTTPError itself", func(t *testing.T) {
		err := fmt.Errorf("error handling request: %w", httph.HTTPError{Code: http.StatusTeapot, Err: context.Canceled})

		var target httph.HTTPError
		is.True(t, errors.As(err, &target))
		is.Equal(t, http.StatusTeapot, target.StatusCode())
	})

	t.Run("unwrap returns nil and errors.Is is false when there is no wrapped error", func(t *testing.T) {
		err := httph.HTTPError{Code: http.StatusBadRequest}

		is.True(t, err.Unwrap() == nil)
		is.True(t, !errors.Is(err, context.Canceled))
	})
}
