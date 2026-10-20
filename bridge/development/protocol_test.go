package development

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFrameContractShouldRejectUnknownOrContradictoryFields(t *testing.T) {
	for _, frame := range []Frame{
		{Version: 1, Kind: "ready"},
		{Version: 1, Kind: "request", ID: "request_one", Operation: "invoke", Deadline: 1, Body: json.RawMessage(`{"payload":"exact-signed-bytes"}`)},
		{Version: 1, Kind: "response", ID: "request_one", Status: 200, Body: json.RawMessage(`{}`)},
		{Version: 1, Kind: "cancel", ID: "request_one"},
		{Version: 1, Kind: "authenticate", Credential: "dedicated-connector"},
	} {
		raw, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeFrame(raw); err != nil {
			t.Fatal("valid frame rejected", err)
		}
	}
	for _, raw := range []string{
		`null`, `{}`, `{"version":2,"kind":"ready"}`, `{"version":1,"kind":"ready","credential":"secret"}`,
		`{"version":1,"kind":"ready","id":"unexpected"}`, `{"version":1,"kind":"cancel"}`,
		`{"version":1,"kind":"request","id":"one","operation":"CONNECT","deadline":1,"body":{}}`,
		`{"version":1,"kind":"request","id":"one","operation":"invoke","deadline":0,"body":{}}`,
		`{"version":1,"kind":"response","id":"one","status":101,"body":{}}`,
		`{"version":1,"kind":"response","id":"../other","status":200,"body":{}}`,
		`{"version":1,"kind":"response","id":"one","status":200,"operation":"invoke","body":{}}`,
		`{"version":1,"kind":"ready"}{}`, strings.Repeat(" ", MaxFrameBytes+1),
		`{"version":1,"kind":"authenticate"}`, `{"version":1,"kind":"authenticate","credential":"one","id":"unexpected"}`,
	} {
		if _, err := DecodeFrame([]byte(raw)); err == nil {
			t.Fatal("unsafe frame accepted")
		}
	}
}
