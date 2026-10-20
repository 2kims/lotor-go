// Package development carries the existing signed bridge protocol over an
// outbound development connection. It does not authorize business operations.
package development

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/2kims/lotor-go/bridge"
)

const (
	ProtocolVersion = 1
	MaxBodyBytes    = bridge.MaximumBodyBytes
	MaxFrameBytes   = MaxBodyBytes + 4096
	Subprotocol     = "lotor-development-v1"
)

// SessionProvider supplies short-lived connector admission, never an application
// secret embedded in a URL. Applications own their ordinary credential refresh.
type Session struct {
	ConnectionID string `json:"connection_id"`
	ConnectorURL string `json:"connector_url"`
	Credential   string `json:"credential"`
	ExpiresAt    int64  `json:"expires_at"`
}

type Frame struct {
	Kind       string          `json:"kind"`
	ID         string          `json:"id,omitempty"`
	Operation  string          `json:"operation,omitempty"`
	Credential string          `json:"credential,omitempty"`
	Body       json.RawMessage `json:"body,omitempty"`
	Version    int             `json:"version"`
	Deadline   int64           `json:"deadline,omitempty"`
	Status     int             `json:"status,omitempty"`
}

func DecodeFrame(raw []byte) (Frame, error) {
	if len(raw) > MaxFrameBytes {
		return Frame{}, bridge.ErrInvalid
	}
	var frame Frame
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&frame) != nil || decoder.Decode(new(any)) != io.EOF || frame.Version != ProtocolVersion || len(frame.ID) > 64 || len(frame.Body) > MaxBodyBytes {
		return Frame{}, bridge.ErrInvalid
	}
	for _, c := range frame.ID {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return Frame{}, bridge.ErrInvalid
		}
	}
	if frame.Kind != "authenticate" && frame.Credential != "" {
		return Frame{}, bridge.ErrInvalid
	}
	switch frame.Kind {
	case "authenticate":
		if frame.ID != "" || frame.Operation != "" || frame.Deadline != 0 || frame.Status != 0 || len(frame.Body) != 0 || frame.Credential == "" || len(frame.Credential) > 8192 {
			return Frame{}, bridge.ErrInvalid
		}
	case "ready":
		if frame.ID != "" || frame.Operation != "" || frame.Deadline != 0 || frame.Status != 0 || len(frame.Body) != 0 {
			return Frame{}, bridge.ErrInvalid
		}
	case "request":
		if frame.ID == "" || frame.Operation != "challenge" && frame.Operation != "invoke" || frame.Deadline <= 0 || frame.Status != 0 || !json.Valid(frame.Body) {
			return Frame{}, bridge.ErrInvalid
		}
	case "response":
		if frame.ID == "" || frame.Operation != "" || frame.Deadline != 0 || frame.Status < 200 || frame.Status > 599 || !json.Valid(frame.Body) {
			return Frame{}, bridge.ErrInvalid
		}
	case "cancel":
		if frame.ID == "" || frame.Operation != "" || frame.Deadline != 0 || frame.Status != 0 || len(frame.Body) != 0 {
			return Frame{}, bridge.ErrInvalid
		}
	default:
		return Frame{}, bridge.ErrInvalid
	}
	return frame, nil
}
