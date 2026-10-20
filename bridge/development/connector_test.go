package development

import (
	"testing"
	"time"
)

func TestSessionRefreshShouldRespectRemainingLease(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, test := range []struct {
		name            string
		remaining, want time.Duration
	}{
		{"ordinary session", 5 * time.Minute, time.Minute},
		{"short session", 4 * time.Second, 2 * time.Second},
		{"near expiry", time.Millisecond, time.Millisecond / 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := Session{ExpiresAt: now.Add(test.remaining).UnixMicro()}
			if got := sessionRefreshAt(session, now).Sub(now); got != test.want {
				t.Fatalf("refresh in %s, want %s", got, test.want)
			}
		})
	}
}
