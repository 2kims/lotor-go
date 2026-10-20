package development

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

func TestConnectionProofShouldBindScopeIdentityPurposeAndShortLifetime(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	proof := ConnectionProof{Scope: bridge.Scope{TenantID: "tenant", ApplicationID: "app", EnvironmentID: "sandbox", OwnerResource: "organization:one"}, ConnectionID: "dvc_one", BindingID: "fnb_one", Nonce: "random-nonce", IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix()}
	signed, err := SignConnectionProof(proof, "runtime-key", private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyConnectionProof(signed, "runtime-key", public, now)
	if err != nil || verified != proof {
		t.Fatal("proof did not preserve identity", err)
	}
	if _, _, err := bridge.VerifyAuthorization(signed, public); err == nil {
		t.Fatal("connector proof accepted as business authorization")
	}
	for _, scenario := range []string{"expired", "future", "key", "signature", "scope", "lifetime"} {
		t.Run(scenario, func(t *testing.T) {
			var err error
			changed, key, clock := signed, "runtime-key", now
			switch scenario {
			case "expired":
				clock = now.Add(30 * time.Second)
			case "future":
				clock = now.Add(-time.Second)
			case "key":
				key = "another-key"
			case "signature":
				changed.Signature = "forged"
			case "scope":
				value := proof
				value.Scope.TenantID = "another"
				changed, err = SignConnectionProof(value, key, private)
				changed.Signature = signed.Signature
			case "lifetime":
				value := proof
				value.ExpiresAt++
				if _, err = SignConnectionProof(value, key, private); err == nil {
					t.Fatal("unbounded proof accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = VerifyConnectionProof(changed, key, public, clock); err == nil {
				t.Fatal("unsafe proof accepted")
			}
		})
	}
}
