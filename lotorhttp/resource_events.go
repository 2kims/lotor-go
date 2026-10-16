package lotorhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type ResourceEventStreamInput struct {
	AttributeKeys         []string `json:"attribute_keys"`
	RetentionDays         int32    `json:"retention_days"`
	AllowCredentialAppend bool     `json:"allow_credential_append"`
}
type ResourceEvent struct {
	ID             string            `json:"id"`
	OccurredAt     time.Time         `json:"occurred_at"`
	Attributes     map[string]string `json:"attributes"`
	Representation string            `json:"representation"`
	Body           []byte            `json:"body"`
}
type ResourceEventMetadata struct {
	ProducerSubject string            `json:"producer_subject"`
	RecordedAt      time.Time         `json:"recorded_at"`
	ID              string            `json:"id"`
	OccurredAt      time.Time         `json:"occurred_at"`
	Attributes      map[string]string `json:"attributes"`
	Representation  string            `json:"representation"`
}
type ResourceEventDetail struct {
	RecordedAt      time.Time `json:"recorded_at"`
	ProducerSubject string    `json:"producer_subject"`
	ResourceEvent
}
type ResourceEventQueryInput struct {
	Filters       map[string][]string `json:"filters"`
	From          time.Time           `json:"from"`
	To            time.Time           `json:"to"`
	ParentQueryID string              `json:"parent_query_id,omitempty"`
}
type ResourceEventQuery struct {
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	ExpiresAt time.Time `json:"expires_at"`
	ID        string    `json:"id"`
}
type ResourceEventPage struct {
	NextCursor *string                 `json:"next_cursor"`
	Items      []ResourceEventMetadata `json:"items"`
}
type ResourceEventBucket struct {
	Start  time.Time        `json:"start"`
	End    time.Time        `json:"end"`
	Counts map[string]int64 `json:"counts"`
}

func resourceEventPath(resource, stream string) string {
	return "/resources/" + url.PathEscape(requiredControl(resource, "resource")) + "/event-streams/" + url.PathEscape(requiredControl(stream, "stream"))
}

// AppendResourceEvent uses an explicitly enabled stream and a credential for
// that exact owning resource. It never confers read or configuration access.
func (c *ResourceClient) AppendResourceEvent(ctx context.Context, resource, stream string, input ResourceEvent) error {
	if input.Attributes == nil {
		input.Attributes = map[string]string{}
	}
	if input.Body == nil {
		input.Body = []byte{}
	}
	_, err := c.request(ctx, http.MethodPost, resourceEventPath(resource, stream)+"/events", nil, input, nil)
	return err
}

// Event operations require a delegated principal. An application credential is
// not substituted for a user's graph read, body access or management authority.
func (c *ControlClient) eventRequest(ctx context.Context, method, path string, input, out any) error {
	if c.userToken == "" {
		return errors.New("resource events require ForUser delegation")
	}
	_, err := c.requestHeadersLimit(ctx, method, path, "", nil, input, out, 6<<20)
	return err
}

func (c *ControlClient) ConfigureResourceEventStream(ctx context.Context, resource, stream string, input ResourceEventStreamInput) error {
	if input.AttributeKeys == nil {
		input.AttributeKeys = []string{}
	}
	return c.eventRequest(ctx, http.MethodPut, resourceEventPath(resource, stream), input, nil)
}

func (c *ControlClient) AppendResourceEvent(ctx context.Context, resource, stream string, input ResourceEvent) error {
	if input.Attributes == nil {
		input.Attributes = map[string]string{}
	}
	if input.Body == nil {
		input.Body = []byte{}
	}
	return c.eventRequest(ctx, http.MethodPost, resourceEventPath(resource, stream)+"/events", input, nil)
}

func (c *ControlClient) CreateResourceEventQuery(ctx context.Context, resource, stream string, input ResourceEventQueryInput) (ResourceEventQuery, error) {
	if input.Filters == nil {
		input.Filters = map[string][]string{}
	}
	var out ResourceEventQuery
	err := c.eventRequest(ctx, http.MethodPost, resourceEventPath(resource, stream)+"/queries", input, &out)
	return out, err
}

func (c *ControlClient) ResourceEvents(ctx context.Context, resource, stream, queryID, cursor string, limit int) (ResourceEventPage, error) {
	var out ResourceEventPage
	if limit < 1 || limit > 100 {
		return out, errors.New("event limit must be between 1 and 100")
	}
	err := c.eventRequest(ctx, http.MethodGet, resourceEventPath(resource, stream)+"/queries/"+url.PathEscape(queryID)+"/events"+pagination(cursor, limit), nil, &out)
	return out, err
}

func (c *ControlClient) ResourceEventHistogram(ctx context.Context, resource, stream, queryID, groupBy string, interval time.Duration) ([]ResourceEventBucket, error) {
	if interval < time.Second || interval > 30*24*time.Hour || interval%time.Second != 0 {
		return nil, errors.New("invalid event histogram interval")
	}
	parameters := url.Values{"group_by": {groupBy}, "interval_seconds": {strconv.FormatInt(int64(interval/time.Second), 10)}}
	var out []ResourceEventBucket
	err := c.eventRequest(ctx, http.MethodGet, resourceEventPath(resource, stream)+"/queries/"+url.PathEscape(queryID)+"/histogram?"+parameters.Encode(), nil, &out)
	return out, err
}

func (c *ControlClient) ResourceEvent(ctx context.Context, resource, stream, eventID string) (ResourceEventDetail, error) {
	var out ResourceEventDetail
	err := c.eventRequest(ctx, http.MethodGet, resourceEventPath(resource, stream)+"/events/"+url.PathEscape(eventID), nil, &out)
	return out, err
}
