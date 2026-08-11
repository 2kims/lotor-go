package lotor_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/2kims/lotor-go/lotor"
)

// Integration test against a running lotord (standalone demo data). Set LOTORD_ADDR (e.g.
// 127.0.0.1:7420); skips otherwise. Proves the Go client speaks LWP end-to-end.
func nonNegativeBalance(t *testing.T, balance int64) uint64 {
	t.Helper()
	if balance < 0 {
		t.Fatalf("negative balance: %d", balance)
	}
	return uint64(balance)
}

func TestClientAgainstLotord(t *testing.T) {
	addr := os.Getenv("LOTORD_ADDR")
	if addr == "" {
		t.Skip("LOTORD_ADDR unset; skipping LWP client integration test")
	}
	ctx := context.Background()
	c, dialErr := lotor.Dial(ctx, addr)
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
	defer c.Close()

	if err := c.Auth("go-key"); err != nil {
		t.Fatalf("auth: %v", err)
	}

	// demo tuples: user:42 view doc:99 (allow); doc:1 (deny)
	if d, err := c.AccessCheck("user:42", "view", "doc:99"); err != nil || !d.Allow {
		t.Fatalf("expected allow, got %+v err=%v", d, err)
	}
	if d, _ := c.AccessCheck("user:42", "view", "doc:1"); d.Allow {
		t.Fatalf("expected deny for doc:1, got allow")
	}
	// org membership inheritance (demo ReBAC): user:42 member org:acme which has feat:sso
	if d, err := c.AccessCheck("user:42", "can_use", "feat:sso"); err != nil || !d.Allow {
		t.Fatalf("expected inherited allow for feat:sso, got %+v err=%v", d, err)
	}

	// prepaid wallet: demo seeds org:acme "credits" = 50. Draw down, hit insufficient, top up.
	bal, err := c.WalletBalance("org:acme", "credits")
	if err != nil || bal < 0 {
		t.Fatalf("wallet balance: got %d err=%v", bal, err)
	}
	d1, err := c.WalletDebit("org:acme", "credits", 10, "go-debit-1")
	if err != nil || !d1.Accepted || d1.Balance != bal-10 {
		t.Fatalf("debit: %+v err=%v (bal was %d)", d1, err, bal)
	}
	// idempotent retry — same key, must not double-debit
	if d2, _ := c.WalletDebit("org:acme", "credits", 10, "go-debit-1"); d2.Balance != d1.Balance {
		t.Fatalf("debit not idempotent: %+v vs %+v", d2, d1)
	}
	// overdraw → rejected, balance unchanged
	if r, _ := c.WalletDebit("org:acme", "credits", nonNegativeBalance(t, d1.Balance)+1, ""); r.Accepted || r.Reason != "insufficient_funds" {
		t.Fatalf("expected insufficient_funds, got %+v", r)
	}
	// top up, then the previously-rejected debit fits
	cr, err := c.WalletCredit("org:acme", "credits", 100, "go-topup-1")
	if err != nil || !cr.Accepted || cr.Balance != d1.Balance+100 {
		t.Fatalf("credit: %+v err=%v", cr, err)
	}

	// one-time addon: a control-issued grant of 5 units on api_calls (max 2), drawn down by a consume.
	g, err := c.AllowanceGrant("org:addon", "api_calls", 5, 0, "", 0, "go-grant-1")
	if err != nil || !g.Accepted || g.UnitsTotal != 5 {
		t.Fatalf("allowance grant: %+v err=%v", g, err)
	}
	if rem, _, _ := c.AllowanceBalance("org:addon", "api_calls"); rem != 5 {
		t.Fatalf("allowance balance = %d, want 5", rem)
	}
	if _, meterErr := c.MeterConsume("org:addon", "api_calls", 2, "go-base"); meterErr != nil { // fill base quota (max 2)
		t.Fatalf("base consume: %v", meterErr)
	}
	mc, err := c.MeterConsume("org:addon", "api_calls", 1, "go-addon")
	if err != nil || mc.Reason != "addon_granted" || mc.GrantDrawn != 1 || mc.GrantRemaining != 4 {
		t.Fatalf("addon consume: %+v err=%v", mc, err)
	}
}

// Dogfooded admin auth: the control plane authorizes its own admin API by asking lotord to
// AUTH.VERIFY the caller's JWT then ACCESS.CHECK `admin` on `control:api`. The demo seeds the JWKS and
// an admin tuple for user:admin. Tokens are signed with the demo key (exp 2100). Needs LOTORD_ADDR.
func TestAdminDogfood(t *testing.T) {
	addr := os.Getenv("LOTORD_ADDR")
	if addr == "" {
		t.Skip("LOTORD_ADDR unset; skipping admin dogfood test")
	}
	// ES256 JWTs signed with lotord's demo private key (kid demo-2026), sub=user:admin / user:42.
	const adminJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlbW8tMjAyNiJ9.eyJzdWIiOiJ1c2VyOmFkbWluIiwib3JnIjoiY29udHJvbCIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.N8BOzaVQ85ufPWHVCIBYigJCGzAoBMdEchJm_epNDBvqiOKUAs3tAtWhoH8KRgkZ3C_6v2pueLK7C-z4DAacaQ"
	const userJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlbW8tMjAyNiJ9.eyJzdWIiOiJ1c2VyOjQyIiwib3JnIjoiY29udHJvbCIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.rmFzcqYWYGiMVk-833B9VkVfEmpj1W5DYfh8EFXtaqasRNZDOu1mY-m-euBFC9z4bu-kTX8xGnEG6GkZbZBlig"

	c, err := lotor.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if authErr := c.Auth("control"); authErr != nil {
		t.Fatalf("auth: %v", authErr)
	}

	// admin token: authentic + authorized.
	v, err := c.AuthVerify(1, adminJWT)
	if err != nil || !v.Valid || v.Subject != "user:admin" {
		t.Fatalf("admin AuthVerify: %+v err=%v", v, err)
	}
	if d, _ := c.AccessCheck(v.Subject, "admin", "control:api"); !d.Allow {
		t.Fatalf("admin should be authorized for control:api")
	}
	// non-admin token: authentic but NOT authorized.
	v2, _ := c.AuthVerify(1, userJWT)
	if !v2.Valid || v2.Subject != "user:42" {
		t.Fatalf("user AuthVerify: %+v", v2)
	}
	if d, _ := c.AccessCheck(v2.Subject, "admin", "control:api"); d.Allow {
		t.Fatalf("user:42 must NOT be authorized for control:api")
	}
}

// Event-driven wallet_low: a debit crossing below the per-account threshold (demo: org:acme/credits,
// threshold 20) pushes a wallet_low EVENT to a subscriber. Needs a running lotord (LOTORD_ADDR).
func TestWalletLowEvent(t *testing.T) {
	addr := os.Getenv("LOTORD_ADDR")
	if addr == "" {
		t.Skip("LOTORD_ADDR unset; skipping wallet_low event test")
	}
	c, err := lotor.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.Auth("go-key"); err != nil {
		t.Fatalf("auth: %v", err)
	}

	// Top up well above the threshold (also re-arms the latch), then subscribe.
	if _, err := c.WalletCredit("org:acme", "credits", 1000, "wl-topup"); err != nil {
		t.Fatalf("top up: %v", err)
	}
	bal, _ := c.WalletBalance("org:acme", "credits")
	got := make(chan lotor.WalletLowEvent, 1)
	if _, err := c.OnWalletLow(func(ev lotor.WalletLowEvent) { got <- ev }); err != nil {
		t.Fatalf("OnWalletLow: %v", err)
	}
	// debit down to 5 (< threshold 20) → crosses → fires once.
	if _, err := c.WalletDebit("org:acme", "credits", nonNegativeBalance(t, bal-5), "wl-debit"); err != nil {
		t.Fatalf("debit: %v", err)
	}
	select {
	case ev := <-got:
		if ev.Wallet != "credits" || ev.Threshold != 20 || ev.Balance >= 20 {
			t.Fatalf("wallet_low event = %+v, want wallet=credits threshold=20 balance<20", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no wallet_low event received")
	}
}
