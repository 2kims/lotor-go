package browseradapter

import "testing"

func TestCatalogDiscoveryRouteBoundary(t *testing.T) {
	t.Parallel()
	for _, item := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "/me/catalogs", true},
		{"GET", "/me/catalogs/cat_one/entries", true},
		{"PUT", "/resources/vault:one/catalog-binding", true},
		{"POST", "/me/catalogs", false},
		{"GET", "/me/catalogs/cat_one/imports", false},
		{"GET", "/me/catalogs/%2F/entries", false},
		{"POST", "/catalogs/cat_one/imports", false},
		{"POST", "/catalogs/cat_one/snapshots/snap/publish", false},
	} {
		if got := resourceRoute(item.method, prefix+item.path); got != item.allowed {
			t.Errorf("%s %s = %v", item.method, item.path, got)
		}
	}
	if !validResourceQuery("GET", prefix+"/me/catalogs/cat_one/entries", "cursor=opaque&limit=10") {
		t.Fatal("discovery pagination rejected")
	}
	if validResourceQuery("GET", prefix+"/me/catalogs", "subject=someone-else") {
		t.Fatal("discovery subject override accepted")
	}
	if validResourceQuery("GET", prefix+"/me/catalogs", "cursor=one&cursor=two") {
		t.Fatal("duplicate cursor accepted")
	}
}
