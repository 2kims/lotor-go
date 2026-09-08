package lotorhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type AccountInvitation struct {
	ID                 string                   `json:"id"`
	Resource           AccountResourceReference `json:"resource"`
	Relation           string                   `json:"relation"`
	Status             string                   `json:"status"`
	ExpiresAt          int64                    `json:"expires_at"`
	EncryptionRequired bool                     `json:"encryption_required"`
}

type AccountInvitationList struct {
	NextCursor  *string             `json:"next_cursor"`
	Invitations []AccountInvitation `json:"invitations"`
}

type AccountInvitationMutation struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// AccountInvitations reads the current user's inbox. Derive this client using
// ForUser; the invitation reference does not confer access before acceptance.
func (c *ControlClient) AccountInvitations(ctx context.Context, cursor string, limit int) (AccountInvitationList, error) {
	var out AccountInvitationList
	if len(cursor) > 2048 || limit < 1 || limit > 100 {
		return out, errors.New("invalid invitation pagination")
	}
	err := c.request(ctx, http.MethodGet, "/me/invitations"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) AcceptAccountInvitation(ctx context.Context, invitationID string) (AccountInvitationMutation, error) {
	return c.accountInvitationAction(ctx, invitationID, "accept")
}

func (c *ControlClient) DeclineAccountInvitation(ctx context.Context, invitationID string) (AccountInvitationMutation, error) {
	return c.accountInvitationAction(ctx, invitationID, "decline")
}

func (c *ControlClient) accountInvitationAction(ctx context.Context, invitationID, action string) (AccountInvitationMutation, error) {
	var out AccountInvitationMutation
	if strings.TrimSpace(invitationID) == "" || len(invitationID) > 256 {
		return out, errors.New("invalid invitation ID")
	}
	err := c.request(ctx, http.MethodPost, "/me/invitations/"+url.PathEscape(invitationID)+"/"+action, "", nil, &out)
	return out, err
}
