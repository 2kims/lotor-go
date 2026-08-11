package lotor

import (
	"bytes"
	"testing"
)

func TestCompositionPinMapEncodingIsDeterministic(t *testing.T) {
	value := capacityPin(CompositionPin{
		Operation:  "operation:consume",
		ResultHash: "abc",
		PoolRef:    "seat_pool:primary",
		Version:    7,
	})
	first := encodeValue(nil, value)
	for range 20 {
		if got := encodeValue(nil, value); !bytes.Equal(got, first) {
			t.Fatal("composition pin map encoding was not deterministic")
		}
	}
	position := 0
	decoded, err := decodeValue(first, &position)
	if err != nil || position != len(first) || decoded.Map["composition_version"].U64 != 7 {
		t.Fatalf("composition pin round trip=%#v err=%v", decoded, err)
	}
}

func TestAuthorizationPinIncludesCompositionSubjectDeterministically(t *testing.T) {
	value := accessPin(CompositionPin{
		Operation:          "operation:view",
		ResultHash:         "abc",
		CompositionSubject: "org:acme",
		Version:            9,
	})
	first := encodeValue(nil, value)
	for range 20 {
		if got := encodeValue(nil, value); !bytes.Equal(got, first) {
			t.Fatal("authorization pin map encoding was not deterministic")
		}
	}
	position := 0
	decoded, err := decodeValue(first, &position)
	if err != nil || position != len(first) ||
		decoded.Map["composition_subject"].asStr() != "org:acme" {
		t.Fatalf("authorization pin round trip=%#v err=%v", decoded, err)
	}
}

func TestPolicyContextIsDeterministicAndSecretFree(t *testing.T) {
	value := policyContext("user:alice", PolicyInput{
		Pin: CompositionPin{
			Operation:          "operation:export",
			ResultHash:         "abc",
			CompositionSubject: "org:acme",
			Version:            11,
		},
		ScopeRef:       "scope:production",
		DestinationRef: "destination:archive",
		RegionRef:      "region:eu",
		EvidenceRefs:   []string{"evidence:z", "evidence:a"},
		RetentionDays:  365,
		Export:         true,
	})
	first := encodeValue(nil, value)
	for range 20 {
		if got := encodeValue(nil, value); !bytes.Equal(got, first) {
			t.Fatal("policy context map encoding was not deterministic")
		}
	}
	position := 0
	decoded, err := decodeValue(first, &position)
	if err != nil || position != len(first) ||
		decoded.Map["composition_subject"].asStr() != "org:acme" ||
		len(decoded.Map["evidence_refs"].List) != 2 ||
		decoded.Map["evidence_refs"].List[0].asStr() != "evidence:a" {
		t.Fatalf("policy context round trip=%#v err=%v", decoded, err)
	}
	for key := range decoded.Map {
		if key == "secret" || key == "credential" || key == "plaintext" {
			t.Fatalf("policy context exposed forbidden key %q", key)
		}
	}
}
