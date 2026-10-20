package lotorhttp

import (
	"context"
	"net/http"
	"net/url"

	"github.com/2kims/lotor-go/bridge/development"
)

// DevelopmentConnection is stable sandbox transport metadata. It contains no
// connector bearer, local destination, signing key or business authority.
type DevelopmentConnection struct {
	RevokedAt   *int64 `json:"revoked_at,omitempty"`
	ID          string `json:"id"`
	Resource    string `json:"resource"`
	EndpointURL string `json:"endpoint_url"`
	Status      string `json:"status"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
}

type DevelopmentConnectionList struct {
	NextCursor  *string                 `json:"next_cursor"`
	Connections []DevelopmentConnection `json:"connections"`
}

type DevelopmentConnectionSession = development.Session

func developmentConnectionPath(resource string) string {
	return "/resources/" + url.PathEscape(requiredControl(resource, "resource")) + "/development-connections"
}

// CreateDevelopmentConnection uses normal delegated resource-manager authority.
// Reconnect does not call this method: it preserves the returned stable ID.
func (client *ControlClient) CreateDevelopmentConnection(ctx context.Context, resource, key string) (DevelopmentConnection, error) {
	var out DevelopmentConnection
	err := client.request(ctx, http.MethodPost, developmentConnectionPath(resource), key, struct{}{}, &out)
	return out, err
}

func (client *ControlClient) DevelopmentConnections(ctx context.Context, resource, cursor string, limit int) (DevelopmentConnectionList, error) {
	var out DevelopmentConnectionList
	err := client.request(ctx, http.MethodGet, developmentConnectionPath(resource)+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (client *ControlClient) DevelopmentConnection(ctx context.Context, resource, connectionID string) (DevelopmentConnection, error) {
	var out DevelopmentConnection
	err := client.request(ctx, http.MethodGet, developmentConnectionPath(resource)+"/"+url.PathEscape(requiredControl(connectionID, "connection ID")), "", nil, &out)
	return out, err
}

func (client *ControlClient) RevokeDevelopmentConnection(ctx context.Context, resource, connectionID string) error {
	return client.request(ctx, http.MethodDelete, developmentConnectionPath(resource)+"/"+url.PathEscape(requiredControl(connectionID, "connection ID")), "", nil, nil)
}

// CreateDevelopmentConnectionSession is explicit manager-issued admission.
// Embedded registered bridges can instead renew with NewProofSessionProvider,
// without persisting a user's browser session or an application secret.
func (client *ControlClient) CreateDevelopmentConnectionSession(ctx context.Context, resource, connectionID string) (DevelopmentConnectionSession, error) {
	var out DevelopmentConnectionSession
	err := client.request(ctx, http.MethodPost, developmentConnectionPath(resource)+"/"+url.PathEscape(requiredControl(connectionID, "connection ID"))+"/sessions", "", struct{}{}, &out)
	return out, err
}
