package development

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLocalAdapterShouldPinDestinationAndStripUnrelatedAuthority(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/functions/invoke" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("local target or authority was caller-controlled")
		}
		_, _ = w.Write([]byte(`{"signed":"response"}`))
	}))
	defer server.Close()
	handler, err := NewLocalHandler(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/functions/invoke", "/admin", "/v1/functions/invoke?url=http://other", "/v1/functions/../admin"} {
		request := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "user-token")
		request.Header.Set("Cookie", "browser=session")
		request.Header.Set("X-Lotor-Secret-Key", "application-secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if path == "/v1/functions/invoke" {
			if response.Code != 200 {
				t.Fatal("fixed local route unavailable")
			}
		} else if response.Code != 404 {
			t.Fatal("arbitrary local path accepted")
		}
	}
	if calls != 1 {
		t.Fatal("caller selected an alternate local destination")
	}
}

func TestLocalAdapterShouldRejectCredentialsRedirectsAndUnsafeConfiguration(t *testing.T) {
	for _, origin := range []string{"", "file:///etc/passwd", "http://user:secret@localhost", "http://localhost/admin", "http://localhost/?url=other", "http://localhost/#fragment", "http://localhost/%2f"} {
		if _, err := NewLocalHandler(origin, nil); err == nil {
			t.Fatal("unsafe local origin accepted")
		}
	}
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer server.Close()
	handler, err := NewLocalHandler(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/v1/functions/invoke", strings.NewReader(`{}`)))
	if response.Code != 502 || followed {
		t.Fatal("local adapter followed redirect")
	}
}

func TestConnectorShouldBoundOrRecoverFromHandlerFailure(t *testing.T) {
	for _, scenario := range []string{"panic", "oversize", "plaintext", "status"} {
		connector := &Connector{options: ConnectorOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			switch scenario {
			case "panic":
				panic("must not escape or be logged")
			case "oversize":
				_, _ = w.Write([]byte(strings.Repeat("x", MaxBodyBytes+1)))
			case "plaintext":
				_, _ = w.Write([]byte("not signed JSON"))
			case "status":
				w.WriteHeader(101)
			}
		})}}
		result := connector.handle(context.Background(), Frame{Version: 1, Kind: "request", ID: "one", Operation: "invoke", Deadline: time.Now().Add(time.Second).UnixMicro(), Body: []byte(`{}`)})
		if result.Status != 502 || strings.Contains(string(result.Body), "must not escape") {
			t.Fatal("unbounded or unsafe local handler result")
		}
	}
}
