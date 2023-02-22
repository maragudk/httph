// Package httph provides HTTP helpers and middleware compatible with net/http.
package httph

import (
	"fmt"
	"net/http"
	"strings"

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
func NoClickjacking(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

// ContentSecurityPolicyOptions for the ContentSecurityPolicy Middleware.
// The field names match policy directives, and only values should be supplied, so no directive names and delimiters.
// Only non-experimental, non-deprecated directives are included.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
type ContentSecurityPolicyOptions struct {
	ChildSrc       string
	ConnectSrc     string
	DefaultSrc     string
	FontSrc        string
	FrameSrc       string
	ImgSrc         string
	ManifestSrc    string
	MediaSrc       string
	ObjectSrc      string
	ScriptSrc      string
	ScriptSrcElem  string
	ScriptSrcAttr  string
	StyleSrc       string
	StyleSrcElem   string
	StyleSrcAttr   string
	WorkerSrc      string
	BaseURI        string
	Sandbox        string
	FormAction     string
	FrameAncestors string
	ReportTo       string
}

// ContentSecurityPolicy is Middleware to set CSP headers.
// By default this is a strict policy, disallowing everything but images, styles, scripts, and fonts from 'self'.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
// See https://infosec.mozilla.org/guidelines/web_security#content-security-policy
func ContentSecurityPolicy(optsFunc func(opts *ContentSecurityPolicyOptions)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			opts := &ContentSecurityPolicyOptions{
				DefaultSrc: "'none'",
				FontSrc:    "'self'",
				ImgSrc:     "'self'",
				ScriptSrc:  "'self'",
				StyleSrc:   "'self'",
			}

			if optsFunc != nil {
				optsFunc(opts)
			}

			var v string
			v += maybeAddDirective("default-src", opts.DefaultSrc)
			v += maybeAddDirective("child-src", opts.ChildSrc)
			v += maybeAddDirective("connect-src", opts.ConnectSrc)
			v += maybeAddDirective("font-src", opts.FontSrc)
			v += maybeAddDirective("frame-src", opts.FrameSrc)
			v += maybeAddDirective("img-src", opts.ImgSrc)
			v += maybeAddDirective("manifest-src", opts.ManifestSrc)
			v += maybeAddDirective("media-src", opts.MediaSrc)
			v += maybeAddDirective("object-src", opts.ObjectSrc)
			v += maybeAddDirective("script-src", opts.ScriptSrc)
			v += maybeAddDirective("script-src-elem", opts.ScriptSrcElem)
			v += maybeAddDirective("script-src-attr", opts.ScriptSrcAttr)
			v += maybeAddDirective("style-src", opts.StyleSrc)
			v += maybeAddDirective("style-src-elem", opts.StyleSrcElem)
			v += maybeAddDirective("style-src-attr", opts.StyleSrcAttr)
			v += maybeAddDirective("worker-src", opts.WorkerSrc)
			v += maybeAddDirective("base-uri", opts.BaseURI)
			v += maybeAddDirective("sandbox", opts.Sandbox)
			v += maybeAddDirective("form-action", opts.FormAction)
			v += maybeAddDirective("frame-ancestors", opts.FrameAncestors)
			v += maybeAddDirective("report-to", opts.ReportTo)

			w.Header().Set("Content-Security-Policy", strings.TrimSuffix(strings.TrimSpace(v), ";"))
			next.ServeHTTP(w, r)
		})
	}
}

func maybeAddDirective(name, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%v %v; ", name, value)
}
