package lotor

import "testing"

func TestDecodeLifecycleResult(t *testing.T) {
	values := []value{
		vBool(true), vStr("reserved"), vStr("inv_1"), vStr("seat_1"),
		vU64(1), vU64(1), vU64(2),
		{Kind: tagI64, I64: 3},
		{Kind: tagI64, I64: 1},
		vU64(42), vStr("evidence"), vU64(7),
	}
	result := decodeLifecycleResult(values)
	if !result.Accepted || result.Reason != "reserved" || result.InvitationID != "inv_1" ||
		result.Active != 1 || result.Reserved != 1 || result.Used != 2 || result.Maximum != 3 ||
		result.Remaining != 1 || result.LogSeq != 42 || result.CompositionVersion != 7 {
		t.Fatalf("unexpected lifecycle result: %+v", result)
	}
}

func TestDecodeOrganizationInvitationList(t *testing.T) {
	invitation := value{Kind: tagMap, Map: map[string]value{
		"invitation_id": vStr("inv_1"), "invitee": vAddr("email:abc"), "role": vStr("member"),
		"expires_at": vU64(123), "seat_id": vStr("seat_1"), "seat_reserved": vBool(true),
	}}
	if invitation.Map["invitee"].asStr() != "email:abc" || !invitation.Map["seat_reserved"].asBool() {
		t.Fatalf("unexpected invitation value: %+v", invitation)
	}
}
