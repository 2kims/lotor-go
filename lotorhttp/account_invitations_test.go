package lotorhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountInvitationInboxPreservesUserAndReadiness(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer invitee" {
			t.Error("lost invitee authority")
		}
		if calls == 4 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			if r.URL.Query().Get("cursor") != "opaque+cursor" || r.URL.Query().Get("limit") != "2" {
				t.Error("lost inbox pagination")
			}
			_, _ = w.Write([]byte(`{"invitations":[{"id":"invite","resource":{"id":"one","resource":"vault:one","type":"vault","name":"One"},"relation":"member","status":"pending_acceptance","expires_at":123,"encryption_required":true}],"next_cursor":"next"}`))
			return
		}
		if r.Method != http.MethodPost || !strings.Contains(r.URL.EscapedPath(), "/me/invitations/invite%2Fone/") {
			t.Error("invalid invitation mutation route")
		}
		status := "declined"
		if strings.HasSuffix(r.URL.Path, "/accept") {
			status = "pending_encryption"
		}
		_, _ = w.Write([]byte(`{"id":"invite/one","status":"` + status + `"}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.ForUser("invitee")
	if err != nil {
		t.Fatal(err)
	}
	page, err := user.AccountInvitations(t.Context(), "opaque+cursor", 2)
	if err != nil || len(page.Invitations) != 1 || page.NextCursor == nil || *page.NextCursor != "next" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if page.Invitations[0].Resource.Resource != "vault:one" || !page.Invitations[0].EncryptionRequired {
		t.Fatal("lost canonical reference or encryption state")
	}
	accepted, err := user.AcceptAccountInvitation(t.Context(), "invite/one")
	if err != nil || accepted.Status != "pending_encryption" {
		t.Fatalf("accept=%+v err=%v", accepted, err)
	}
	declined, err := user.DeclineAccountInvitation(t.Context(), "invite/one")
	if err != nil || declined.Status != "declined" {
		t.Fatalf("decline=%+v err=%v", declined, err)
	}
	if _, err = user.AcceptAccountInvitation(t.Context(), "invite/one"); err == nil {
		t.Fatal("denial ignored")
	}
	if _, err = user.AcceptAccountInvitation(t.Context(), ""); err == nil {
		t.Fatal("empty ID accepted")
	}
	if _, err = user.AccountInvitations(t.Context(), "", 101); err == nil {
		t.Fatal("invalid pagination accepted")
	}
	if calls != 4 {
		t.Fatalf("unexpected retries or invalid requests: %d", calls)
	}
}
