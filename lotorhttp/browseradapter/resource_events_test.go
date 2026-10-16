package browseradapter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventAdapterPreservesLargeOpaqueBodiesAndBoundedQueryFilters(t *testing.T) {
	for _, kind := range []string{"append", "query", "detail"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte(`{}`)
			method := "POST"
			path := "/resources/project%3Aone/event-streams/audit/events"
			switch kind {
			case "append":
				body, _ = json.Marshal(map[string]any{"id": "event", "body": base64.StdEncoding.EncodeToString(make([]byte, 4<<20))})
			case "query":
				path = "/resources/project%3Aone/event-streams/audit/queries"
				filters := map[string][]string{}
				for _, key := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
					filters[key] = make([]string, 16)
					for i := range filters[key] {
						filters[key][i] = strings.Repeat("<", 256)
					}
				}
				body, _ = json.Marshal(map[string]any{"filters": filters})
			case "detail":
				method = "GET"
				path += "/event"
			}
			responseBody, _ := json.Marshal(map[string]string{"body": base64.StdEncoding.EncodeToString(make([]byte, 4<<20))})
			a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer user-session" || r.Header.Get("X-Lotor-Secret-Key") != "" {
					t.Error("event request escalated authority")
				}
				got, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(got, body) {
					t.Error("event body changed")
				}
				_, _ = w.Write(responseBody)
			})
			r := request(method, path)
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "user-session"})
			r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
			r.Header.Set("X-Lotor-CSRF", "proof")
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), responseBody) {
				t.Fatalf("event adapter bounds/status=%d", w.Code)
			}
		})
	}
}
