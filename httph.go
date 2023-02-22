// Package httph provides HTTP helpers and middleware compatible with net/http.
package httph

import (
	"fmt"
	"net/http"

	"github.com/mitchellh/mapstructure"
)

type validator interface {
	Validate() error
}

// FormHandler takes a function that is like a regular http.Handler, except it also receives a struct with values
// parsed from http.Request.ParseForm. Any parsing errors will result in http.StatusBadRequest.
// Uses reflection under the hood.
// If the request struct satisfies the validator interface, also use it to validate the struct.
func FormHandler[Req any](h func(http.ResponseWriter, *http.Request, Req)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		form := map[string]any{}
		for k := range r.Form {
			if len(r.Form[k]) > 1 {
				form[k] = r.Form[k]
				continue
			}
			form[k] = r.Form.Get(k)
		}
		if err := mapstructure.WeakDecode(form, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req, ok := any(req).(validator); ok {
			if err := req.Validate(); err != nil {
				http.Error(w, fmt.Sprintf("invalid form: %v", err), http.StatusBadRequest)
				return
			}
		}

		h(w, r, req)
	}
}

// Middleware is a function that takes an http.Handler and returns an http.Handler.
// This is a common middleware pattern in net/http.
type Middleware = func(next http.Handler) http.Handler

// NoClickjacking is Middleware which sets headers to disallow frame embedding and XSS protection for older browsers.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
func NoClickjacking(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}
