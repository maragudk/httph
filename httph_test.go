package httph_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maragudk/is"

	"github.com/maragudk/httph"
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

		mux := http.NewServeMux()
		mux.HandleFunc("/", httph.NoClickjacking(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

		mux.ServeHTTP(res, req)

		is.Equal(t, http.StatusOK, res.Result().StatusCode)
		is.Equal(t, "deny", res.Result().Header.Get("X-Frame-Options"))
		is.Equal(t, "1; mode=block", res.Result().Header.Get("X-XSS-Protection"))
	})
}
