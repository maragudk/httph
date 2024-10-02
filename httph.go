// Package httph provides HTTP helpers and middleware compatible with net/http.
package httph

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"regexp"
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

// statusCodeGiver is something that can give a status code.
type statusCodeGiver interface {
	StatusCode() int
}

// maxSizeGiver is something that can give a max size in bytes.
type maxSizeGiver interface {
	MaxSizeBytes() int64
}

// JSONHandler takes a function that is like a regular http.Handler, except it also receives a struct with values
// parsed from the request body as JSON. The function also returns a struct that will be encoded as JSON in the response.
// If either the response struct or error satisfy the statusCodeGiver interface, the given HTTP status code is returned.
func JSONHandler[Req any, Res any](h func(http.ResponseWriter, *http.Request, Req) (Res, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req

		if req, ok := any(req).(maxSizeGiver); ok {
			r.Body = http.MaxBytesReader(w, r.Body, req.MaxSizeBytes())
		}

		// Try reading a request body, skip if there is none
		br := bufio.NewReader(r.Body)
		if _, err := br.Peek(1); err == nil {
			dec := json.NewDecoder(br)

			if err := dec.Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeResponse(w, errorResponse{
					Error: fmt.Errorf("error decoding request body as JSON: %w", err).Error(),
				})
				return
			}
		}

		res, err := h(w, r, req)
		if err != nil {
			code := http.StatusInternalServerError
			if err, ok := err.(statusCodeGiver); ok {
				code = err.StatusCode()
			}

			w.WriteHeader(code)
			writeResponse(w, errorResponse{Error: err.Error()})
			return
		}

		// Try encoding to a buffer first, to catch any encoding errors
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(res); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeResponse(w, errorResponse{
				Error: fmt.Errorf("error encoding response body as JSON: %w", err).Error(),
			})
			return
		}

		code := http.StatusOK
		if res, ok := any(res).(statusCodeGiver); ok {
			code = res.StatusCode()
		}
		w.WriteHeader(code)

		// There's not much we can do about an error here, so ignore it
		_, _ = io.Copy(w, &b)
	}
}

func writeResponse(w io.Writer, v any) {
	// If there's an error here, it's probably an error writing to the client that we can't do anything about, so ignore it.
	_ = json.NewEncoder(w).Encode(v)
}

type errorResponse struct {
	Error string
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

//go:embed goget.gohtml
var goGetFS embed.FS

type GoGetOptions struct {
	Domain    string   // Domain to serve URLs for, for example: "maragu.dev"
	Modules   []string // Lit of module names, for example: "httph", "foo"
	URLPrefix string   // URL prefix to serve the module from, for example: "https://github.com/maragudk"
}

// GoGet is Middleware to support redirecting go get requests to module VCS URLs, popularly known as vanity URLs.
// See https://www.maragu.dev/blog/til-http-middleware-for-custom-go-module-paths
func GoGet(opts GoGetOptions) Middleware {
	if opts.Domain == "" {
		panic("invalid domain")
	}

	if len(opts.Modules) == 0 {
		panic("no modules")
	}
	for _, m := range opts.Modules {
		if m == "" {
			panic("invalid module")
		}
	}

	if !strings.HasPrefix(opts.URLPrefix, "http") {
		panic("invalid URL prefix")
	}
	opts.URLPrefix = strings.TrimSuffix(opts.URLPrefix, "/")

	t := template.Must(template.ParseFS(goGetFS, "goget.gohtml"))

	modules := map[string]struct{}{}
	for _, m := range opts.Modules {
		modules[m] = struct{}{}
	}

	type Data struct {
		Domain    string
		Module    string
		URLPrefix string
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Split(r.URL.Path, "/")
			module := parts[1]
			// Exit early if the module is not in the list of modules
			if _, ok := modules[module]; !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Redirect to the module's URL if the request is not a go-get request
			goGet := r.URL.Query().Get("go-get")
			if goGet != "1" {
				http.Redirect(w, r, fmt.Sprintf("%v/%v", opts.URLPrefix, module), http.StatusPermanentRedirect)
				return
			}

			data := Data{
				Domain:    opts.Domain,
				Module:    module,
				URLPrefix: opts.URLPrefix,
			}
			if err := t.Execute(w, data); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		})
	}
}

// versionedAssetMatcher matches versioned assets like "app.abc123.js".
// See https://regex101.com/r/bGfflm/latest
var versionedAssetMatcher = regexp.MustCompile(`^(?P<name>[^.]+)\.[a-z0-9]+(?P<extension>\.[a-z0-9]+)$`)

// VersionedAssets is Middleware to help serve versioned assets without the version.
// It basically strips the version from the asset path and forwards the request, probably to a static file handler.
func VersionedAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if versionedAssetMatcher.MatchString(r.URL.Path) {
			r.URL.Path = versionedAssetMatcher.ReplaceAllString(r.URL.Path, `$1$2`)
		}

		next.ServeHTTP(w, r)
	})
}
