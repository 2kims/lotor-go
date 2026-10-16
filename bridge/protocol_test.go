package bridge

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestManifestDigestHasStableCanonicalBytesAndDoesNotMutateInput(t *testing.T) {
	input, output := strings.Repeat("a", 64), strings.Repeat("b", 64)
	manifest := Manifest{ProtocolVersion: 1, Functions: []Function{
		{Name: "customer.z", Version: "1", InputSchemaDigest: input, OutputSchemaDigest: output},
		{Name: "customer.a", Version: "1", InputSchemaDigest: input, OutputSchemaDigest: output},
	}}
	canonical := `{"protocol_version":1,"functions":[{"name":"customer.a","version":"1","input_schema_digest":"` + input + `","output_schema_digest":"` + output + `"},{"name":"customer.z","version":"1","input_schema_digest":"` + input + `","output_schema_digest":"` + output + `"}]}`
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	actual, err := ManifestDigest(manifest)
	if err != nil || actual != want {
		t.Fatalf("canonical manifest bytes changed: got=%s want=%s err=%v", actual, want, err)
	}
	if manifest.Functions[0].Name != "customer.z" {
		t.Fatal("digest calculation mutated the caller's registration order")
	}
}
