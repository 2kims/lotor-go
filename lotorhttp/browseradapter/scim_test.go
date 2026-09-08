package browseradapter

import "testing"

func TestSCIMSetupRouteBoundary(t *testing.T) {
	base := prefix + "/resources/organization%3Aacme/scim-directories"
	for _, scenario := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", base, true},
		{"POST", base, true},
		{"GET", base + "/res_directory", true},
		{"PUT", base + "/res_directory", true},
		{"DELETE", base + "/res_directory", false},
		{"GET", base + "/%2Fother", false},
		{"POST", base + "/res_directory/Users", false},
		{"POST", prefix + "/scim/v2/directories/res_directory/Users", false},
	} {
		if got := resourceRoute(scenario.method, scenario.path); got != scenario.allowed {
			t.Errorf("%s %s allowed=%t", scenario.method, scenario.path, got)
		}
	}
	if !validResourceQuery("GET", base, "cursor=opaque&limit=10") {
		t.Fatal("SCIM pagination rejected")
	}
	for _, query := range []string{"cursor=one&cursor=two", "subject=other", "tenant_id=foreign"} {
		if validResourceQuery("GET", base, query) {
			t.Fatalf("unexpected query accepted: %s", query)
		}
	}
}
