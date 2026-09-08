package browseradapter

import "testing"

func TestOrganizationRelayRouteAllowlist(t *testing.T) {
	base := prefix + "/resources/organization%3Aacme/e2ee/function-bindings"
	for _, scenario := range []struct {
		method, path string
		allowed      bool
	}{
		{"POST", base, true},
		{"POST", base + "/efb_acme/challenge", true},
		{"GET", base + "/efb_acme/challenge", false},
		{"POST", base + "/%2Fother/challenge", false},
		{"GET", base + "/efb_acme", true},
		{"DELETE", base + "/efb_acme", true},
		{"GET", base, true},
		{"PUT", base + "/efb_acme", false},
		{"POST", base + "/efb_acme/register", false},
		{"DELETE", base + "/%2Fother", false},
		{"POST", prefix + "/e2ee-relay/bindings/efb_acme/register", false},
	} {
		if actual := resourceRoute(scenario.method, scenario.path); actual != scenario.allowed {
			t.Errorf("%s %s allowed=%t", scenario.method, scenario.path, actual)
		}
	}
}
