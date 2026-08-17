package lotor

import "testing"

func TestDecodeSubjectKeyMutation(t *testing.T) {
	result := decodeSubjectKeyMutation([]value{vBool(true), vStr("registered"), vStr("key_1"), vU64(42)})
	if !result.Accepted || result.Reason != "registered" || result.KeyID != "key_1" || result.LogSeq != 42 {
		t.Fatalf("unexpected mutation: %+v", result)
	}
}

func TestDecodeResourceGrantMutation(t *testing.T) {
	result := decodeResourceGrantMutation([]value{vBool(true), vStr("activated"), vStr("grant_1"), vStr("active"), vU64(43)})
	if !result.Accepted || result.Reason != "activated" || result.GrantID != "grant_1" || result.Status != "active" || result.LogSeq != 43 {
		t.Fatalf("unexpected grant mutation: %+v", result)
	}
}
