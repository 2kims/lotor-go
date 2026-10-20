package development

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

// NewLocalHandler is the optional container adapter for one explicitly selected
// local bridge origin. It is not a public proxy and never follows redirects or
// forwards a caller-selected host, path, authorization or cookie.
func NewLocalHandler(origin string, client *http.Client) (http.Handler, error) {
	parsed, err := url.Parse(origin)
	if err != nil || origin != strings.TrimSpace(origin) || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(origin, "#") || parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, bridge.ErrInvalid
	}
	parsed.Path = ""
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil // A fixed local bridge must not traverse HTTP_PROXY.
		client = &http.Client{Transport: transport}
	}
	isolated := *client
	isolated.Jar = nil
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	isolated.Timeout = time.Minute
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != "/v1/functions/challenge" && r.URL.Path != "/v1/functions/invoke" {
			http.Error(w, "bridge route not found", 404)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), "POST", parsed.String()+r.URL.Path, http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		if err != nil {
			http.Error(w, "bridge unavailable", 502)
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := isolated.Do(request)
		if err != nil {
			http.Error(w, "bridge unavailable", 502)
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
		if err != nil || len(body) > MaxBodyBytes || response.StatusCode >= 300 && response.StatusCode < 400 {
			http.Error(w, "bridge unavailable", 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(body)
	}), nil
}
