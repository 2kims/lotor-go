package lotorhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Base64URLBytes []byte

func (value *Base64URLBytes) UnmarshalJSON(raw []byte) error {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil || encoded == "" || strings.Contains(encoded, "=") {
		return errors.New("invalid unpadded base64url bytes")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return errors.New("invalid unpadded base64url bytes")
	}
	*value = decoded
	return nil
}

func (value Base64URLBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(value))
}

type ResourceLinkChange struct {
	Cascade         *bool  `json:"cascade,omitempty"`
	Action          string `json:"action"`
	LinkID          string `json:"link_id,omitempty"`
	Collaborator    string `json:"collaborator,omitempty"`
	Relation        string `json:"relation,omitempty"`
	Subject         string `json:"subject,omitempty"`
	Email           string `json:"email,omitempty"`
	SubjectResource string `json:"subject_resource,omitempty"`
	SubjectRelation string `json:"subject_relation,omitempty"`
	Provisioning    string `json:"provisioning,omitempty"`
	Delivery        string `json:"delivery,omitempty"`
}

type ResourceLinkCandidateSearchInput struct {
	Query    string   `json:"query"`
	Relation string   `json:"relation"`
	Cursor   string   `json:"cursor,omitempty"`
	Kinds    []string `json:"kinds,omitempty"`
	Limit    int      `json:"limit,omitempty"`
}

type ResourceLinkCandidate struct {
	Kind            string `json:"kind"`
	Subject         string `json:"subject,omitempty"`
	Resource        string `json:"resource,omitempty"`
	SubjectRelation string `json:"subject_relation,omitempty"`
	DisplayName     string `json:"display_name"`
	Email           string `json:"email,omitempty"`
	LinkState       string `json:"link_state"`
	Reason          string `json:"reason,omitempty"`
	Selectable      bool   `json:"selectable"`
}

type ResourceLinkCandidateSearchResult struct {
	NextCursor *string                 `json:"next_cursor"`
	Candidates []ResourceLinkCandidate `json:"candidates"`
}

type ResourceLinkEnvelopeSubmission struct {
	ManifestItemID  string `json:"manifest_item_id"`
	EncryptionSuite string `json:"encryption_suite"`
	Ciphertext      string `json:"ciphertext"`
	AADHash         string `json:"aad_hash"`
	Issuer          string `json:"issuer"`
	IssuerKeyID     string `json:"issuer_key_id"`
	Signature       string `json:"signature"`
}

type ResourceLinkOutcome struct {
	LinkID   string `json:"link_id,omitempty"`
	Resource string `json:"resource"`
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Allowed  bool   `json:"allowed"`
}

type ResourceLinkKeyRequirement struct {
	ManifestItemID      string         `json:"manifest_item_id"`
	GrantID             string         `json:"grant_id"`
	Resource            string         `json:"resource"`
	Relation            string         `json:"relation"`
	KeyResource         string         `json:"key_resource"`
	KeyVersion          string         `json:"key_version"`
	RecipientSubject    string         `json:"recipient_subject"`
	RecipientKeyID      string         `json:"recipient_key_id"`
	EncryptionAlgorithm string         `json:"encryption_algorithm"`
	InvitationID        string         `json:"invitation_id,omitempty"`
	Activation          string         `json:"activation,omitempty"`
	PublicKey           Base64URLBytes `json:"public_key"`
}

type ResourceLinkRevisions struct {
	Customer string `json:"customer"`
	Graph    string `json:"graph"`
	Policy   string `json:"policy"`
	Identity string `json:"identity"`
	Billing  string `json:"billing"`
	Seat     string `json:"seat"`
	Key      string `json:"key"`
}
type ResourceLinkCapacity struct {
	Scope   string `json:"scope"`
	Before  int64  `json:"before"`
	After   int64  `json:"after"`
	Claim   int64  `json:"claim"`
	Release int64  `json:"release"`
}
type ResourceLinkBilling struct {
	CurrentQuantity    int64 `json:"current_quantity"`
	NextCycleQuantity  int64 `json:"next_cycle_quantity"`
	Increase           int64 `json:"increase"`
	NextCycleReduction int64 `json:"next_cycle_reduction"`
}
type ResourceLinkInvitationAction struct {
	InvitationID string `json:"invitation_id"`
	Action       string `json:"action"`
	Reason       string `json:"reason,omitempty"`
}
type ResourceLinkImpact struct {
	ImpactedResources []string `json:"impacted_resources"`
	RetainedResources []string `json:"retained_resources"`
	RekeyResources    []string `json:"rekey_resources"`
}

type ResourceLinkResult struct {
	Revisions         ResourceLinkRevisions          `json:"revisions"`
	Resource          string                         `json:"resource"`
	Status            string                         `json:"status"`
	FailureReason     string                         `json:"failure_reason,omitempty"`
	Impact            ResourceLinkImpact             `json:"impact"`
	KeyRequirements   []ResourceLinkKeyRequirement   `json:"key_requirements"`
	InvitationActions []ResourceLinkInvitationAction `json:"invitation_actions"`
	Outcomes          []ResourceLinkOutcome          `json:"outcomes"`
	Capacity          ResourceLinkCapacity           `json:"capacity"`
	Billing           ResourceLinkBilling            `json:"billing"`
	ExpiresAt         int64                          `json:"expires_at"`
	Committable       bool                           `json:"committable"`
	Idempotent        bool                           `json:"idempotent"`
}

type ResourceLinkPreflight struct {
	Token  string
	Result ResourceLinkResult
}

type ResourceLinkSendInput struct {
	Changes []ResourceLinkChange `json:"changes"`
}
type ResourceLinkSendResult struct {
	Preflight ResourceLinkPreflight
	Committed ResourceLinkResult
}

// ResourceSubjectAccessCheck is the current effective-access decision for one
// exact subject and one exact resource. It intentionally contains no graph,
// relation, collaborator, or identity metadata.
type ResourceSubjectAccessCheck struct {
	Resource string `json:"resource"`
	Subject  string `json:"subject"`
	Allowed  bool   `json:"allowed"`
}

type UnlinkResult struct {
	ID            string   `json:"id"`
	Resource      string   `json:"resource"`
	Status        string   `json:"status"`
	RekeySubjects []string `json:"rekey_subjects"`
	RekeyRequired bool     `json:"rekey_required"`
	Idempotent    bool     `json:"idempotent"`
}

type CollaboratorPathStep struct {
	Resource        string `json:"resource"`
	SubjectRelation string `json:"subject_relation"`
}
type CollaboratorPath struct {
	Type            string                 `json:"type"`
	Relation        string                 `json:"relation"`
	Group           string                 `json:"group,omitempty"`
	SubjectRelation string                 `json:"subject_relation,omitempty"`
	LinkID          string                 `json:"link_id,omitempty"`
	Via             []CollaboratorPathStep `json:"via"`
}
type ResourceCollaborator struct {
	Access          *CollaboratorAccess    `json:"access,omitempty"`
	Recipient       *CollaboratorRecipient `json:"recipient,omitempty"`
	Status          string                 `json:"status"`
	Resource        string                 `json:"resource,omitempty"`
	DisplayName     string                 `json:"display_name,omitempty"`
	Email           string                 `json:"email,omitempty"`
	Kind            string                 `json:"kind"`
	SubjectRelation string                 `json:"subject_relation,omitempty"`
	LinkID          string                 `json:"link_id,omitempty"`
	ID              string                 `json:"id"`
	Relations       []string               `json:"relations"`
	MemberCount     int64                  `json:"member_count,omitempty"`
	ExpiresAt       int64                  `json:"expires_at,omitempty"`
}
type CollaboratorAccess struct {
	Paths  []CollaboratorPath `json:"paths"`
	Direct bool               `json:"direct"`
}
type CollaboratorRecipient struct {
	Type    string `json:"type"`
	Subject string `json:"subject,omitempty"`
	Display string `json:"display,omitempty"`
}
type ResourceCollaboratorList struct {
	NextCursor    *string                `json:"next_cursor"`
	Resource      string                 `json:"resource"`
	Collaborators []ResourceCollaborator `json:"collaborators"`
}
type ResourceCollaboratorListOptions struct {
	Direct          *bool
	Kind            string
	Email           string
	Subject         string
	ResourceSubject string
	ViaGroup        string
	View            string
	Status          string
	Cursor          string
	Search          string
	Kinds           []string
	Statuses        []string
	Relations       []string
	Limit           int
}

type ResourceSearchResourceFilters struct {
	References map[string]string `json:"references,omitempty"`
	Search     string            `json:"search,omitempty"`
	Resources  []string          `json:"resources,omitempty"`
	Types      []string          `json:"types,omitempty"`
	Parent     string            `json:"parent,omitempty"`
	Statuses   []string          `json:"statuses,omitempty"`
}
type ResourceSearchCollaboratorFilters struct {
	Direct          *bool    `json:"direct,omitempty"`
	Search          string   `json:"search,omitempty"`
	Email           string   `json:"email,omitempty"`
	View            string   `json:"view,omitempty"`
	ResourceSubject string   `json:"resource_subject,omitempty"`
	Subjects        []string `json:"subjects,omitempty"`
	Kinds           []string `json:"kinds,omitempty"`
	Relations       []string `json:"relations,omitempty"`
	Statuses        []string `json:"statuses,omitempty"`
	ViaGroups       []string `json:"via_groups,omitempty"`
}
type ResourceSearchFilters struct {
	Resource     *ResourceSearchResourceFilters     `json:"resource,omitempty"`
	Collaborator *ResourceSearchCollaboratorFilters `json:"collaborator,omitempty"`
}
type ResourceSearchSort struct {
	Field     string `json:"field,omitempty"`
	Direction string `json:"direction,omitempty"`
}
type ResourceSearchPage struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}
type ResourceSearchInput struct {
	Filters *ResourceSearchFilters `json:"filters,omitempty"`
	Sort    *ResourceSearchSort    `json:"sort,omitempty"`
	Page    *ResourceSearchPage    `json:"page,omitempty"`
	Include []string               `json:"include,omitempty"`
}
type ResourceSearchParent struct {
	Resource     string `json:"resource"`
	ResourceType string `json:"resource_type"`
	DisplayName  string `json:"display_name"`
}
type ResourceSearchResult struct {
	Parent              *ResourceSearchParent  `json:"parent,omitempty"`
	References          map[string]string      `json:"references,omitempty"`
	Resource            string                 `json:"resource"`
	ResourceType        string                 `json:"resource_type"`
	DisplayName         string                 `json:"display_name"`
	Status              string                 `json:"status"`
	CollaboratorMatches []ResourceCollaborator `json:"collaborator_matches,omitempty"`
}
type ResourceSearchList struct {
	NextCursor *string                `json:"next_cursor"`
	Resources  []ResourceSearchResult `json:"resources"`
}

func (c *ControlClient) SearchResourceLinkCandidates(ctx context.Context, resource string, input ResourceLinkCandidateSearchInput) (ResourceLinkCandidateSearchResult, error) {
	var out ResourceLinkCandidateSearchResult
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	if err := validateCandidateSearch(&input); err != nil {
		return out, err
	}
	err := c.strictRequest(ctx, http.MethodPost, graphResourcePath(resource)+"/link-candidates/search", "", nil, input, &out)
	if err == nil {
		err = validateCandidateSearchResult(out)
	}
	return out, err
}

func (c *ControlClient) PreflightResourceLinks(ctx context.Context, resource string, changes []ResourceLinkChange) (ResourceLinkPreflight, error) {
	var out ResourceLinkResult
	if err := c.requireResourceGraphUser(); err != nil {
		return ResourceLinkPreflight{}, err
	}
	resource, err := graphString(resource, "resource", 512)
	if err != nil {
		return ResourceLinkPreflight{}, err
	}
	if len(changes) < 1 || len(changes) > 1000 {
		return ResourceLinkPreflight{}, errors.New("changes must contain between 1 and 1000 items")
	}
	for _, change := range changes {
		if err = validateLinkChange(change); err != nil {
			return ResourceLinkPreflight{}, err
		}
	}
	headers, err := c.strictRequestHeaders(ctx, http.MethodPost, graphResourcePath(resource)+"/links/preflight", "", nil, struct {
		Changes []ResourceLinkChange `json:"changes"`
	}{changes}, &out)
	if err != nil {
		return ResourceLinkPreflight{}, err
	}
	token := strings.TrimSpace(headers.Get("Lotor-Link-Token"))
	if token, err = graphString(token, "link token", 512); err != nil {
		return ResourceLinkPreflight{}, errors.New("Lotor link preflight response is missing its token")
	}
	if err = validateResourceLinkResult(out, resource); err != nil {
		return ResourceLinkPreflight{}, err
	}
	return ResourceLinkPreflight{Result: out, Token: token}, nil
}

func (c *ControlClient) CommitResourceLinks(ctx context.Context, resource string, preflight ResourceLinkPreflight, envelopes []ResourceLinkEnvelopeSubmission) (ResourceLinkResult, error) {
	var out ResourceLinkResult
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	resource, err := graphString(resource, "resource", 512)
	if err != nil {
		return out, err
	}
	token, err := graphString(preflight.Token, "link token", 512)
	if err != nil {
		return out, err
	}
	if preflight.Result.Resource != resource {
		return out, errors.New("link preflight resource does not match commit resource")
	}
	if len(envelopes) > 10000 {
		return out, errors.New("envelopes cannot contain more than 10000 items")
	}
	for _, envelope := range envelopes {
		if err = validateLinkEnvelope(envelope); err != nil {
			return out, err
		}
	}
	body := struct {
		Envelopes []ResourceLinkEnvelopeSubmission `json:"envelopes,omitempty"`
	}{envelopes}
	err = c.strictRequest(ctx, http.MethodPost, graphResourcePath(resource)+"/links/commit", "", http.Header{"Lotor-Link-Token": []string{token}}, body, &out)
	if err == nil {
		err = validateResourceLinkResult(out, resource)
	}
	return out, err
}

func (c *ControlClient) SendResourceLinks(ctx context.Context, resource string, input ResourceLinkSendInput) (ResourceLinkSendResult, error) {
	preflight, err := c.PreflightResourceLinks(ctx, resource, input.Changes)
	if err != nil {
		return ResourceLinkSendResult{}, err
	}
	if !preflight.Result.Committable {
		code := preflight.Result.FailureReason
		if code == "" {
			code = "link_denied"
		}
		return ResourceLinkSendResult{}, &ControlError{Status: http.StatusConflict, Code: code, Message: code}
	}
	committed, err := c.CommitResourceLinks(ctx, resource, preflight, nil)
	return ResourceLinkSendResult{Preflight: preflight, Committed: committed}, err
}

func (c *ControlClient) UnlinkResource(ctx context.Context, resource, linkID, idempotencyKey string) (UnlinkResult, error) {
	var out UnlinkResult
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	resource, err := graphString(resource, "resource", 512)
	if err != nil {
		return out, err
	}
	linkID, err = graphString(linkID, "link ID", 256)
	if err != nil {
		return out, err
	}
	err = c.strictRequest(ctx, http.MethodDelete, graphResourcePath(resource)+"/links/"+url.PathEscape(linkID), idempotencyKey, nil, nil, &out)
	if err == nil && (out.Resource != resource || out.Status != "revoked") {
		err = errors.New("invalid Lotor unlink response")
	}
	return out, err
}

func (c *ControlClient) ResourceCollaborators(ctx context.Context, resource string, options ResourceCollaboratorListOptions) (ResourceCollaboratorList, error) {
	var out ResourceCollaboratorList
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	resource, err := graphString(resource, "resource", 512)
	if err != nil {
		return out, err
	}
	query, err := collaboratorQuery(options)
	if err != nil {
		return out, err
	}
	err = c.strictRequest(ctx, http.MethodGet, graphResourcePath(resource)+"/collaborators"+query, "", nil, nil, &out)
	if err == nil {
		err = validateCollaboratorList(out, resource)
	}
	return out, err
}

// CheckResourceSubjectAccess performs a server-to-server authorization check
// using application authority. A delegated user client is rejected so a user
// bearer token can never be confused with, or unnecessarily disclosed to, the
// application-only decision endpoint.
func (c *ControlClient) CheckResourceSubjectAccess(ctx context.Context, resource, subject string) (ResourceSubjectAccessCheck, error) {
	var out ResourceSubjectAccessCheck
	if err := c.requireApplicationAuthority(); err != nil {
		return out, err
	}
	resource, err := graphString(resource, "resource", 512)
	if err != nil {
		return out, err
	}
	subject, err = graphSubject(subject)
	if err != nil {
		return out, err
	}
	input := struct {
		Subject string `json:"subject"`
	}{Subject: subject}
	err = c.strictRequest(ctx, http.MethodPost, graphResourcePath(resource)+"/subject-access/check", "", nil, input, &out)
	if err == nil && (out.Resource != resource || out.Subject != subject) {
		err = errors.New("invalid Lotor subject access response")
	}
	return out, err
}

func (c *ControlClient) SearchResources(ctx context.Context, input ResourceSearchInput) (ResourceSearchList, error) {
	var out ResourceSearchList
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	if err := validateResourceSearch(input); err != nil {
		return out, err
	}
	err := c.strictRequest(ctx, http.MethodPost, "/resources/search", "", nil, input, &out)
	if err == nil {
		err = validateResourceSearchList(out)
	}
	return out, err
}

func (c *ControlClient) strictRequest(ctx context.Context, method, path, key string, headers http.Header, body, out any) error {
	_, err := c.strictRequestHeaders(ctx, method, path, key, headers, body, out)
	return err
}

func (c *ControlClient) strictRequestHeaders(ctx context.Context, method, path, key string, headers http.Header, body, out any) (http.Header, error) {
	var raw json.RawMessage
	responseHeaders, err := c.requestHeaders(ctx, method, path, key, headers, body, &raw)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil {
		return nil, errors.New("invalid Lotor response")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid Lotor response")
	}
	return responseHeaders, nil
}

func graphResourcePath(resource string) string {
	return "/resources/" + url.PathEscape(strings.TrimSpace(resource))
}

func (c *ControlClient) requireResourceGraphUser() error {
	if c.userToken == "" {
		return errors.New("resource collaboration requires ForUser delegation")
	}
	return nil
}

func (c *ControlClient) requireApplicationAuthority() error {
	if c.userToken != "" {
		return errors.New("operation requires application authority")
	}
	return nil
}

func graphSubject(value string) (string, error) {
	value, err := graphString(value, "subject", 512)
	if err != nil || strings.ContainsAny(value, " \t\r\n/?#") {
		return "", errors.New("subject is invalid")
	}
	return value, nil
}

func graphString(value, name string, maximum int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return "", fmt.Errorf("%s is invalid", name)
	}
	return value, nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
func validPage(limit int) bool { return limit >= 0 && limit <= 100 }
func validateCandidateSearch(input *ResourceLinkCandidateSearchInput) error {
	query, err := graphString(input.Query, "query", 256)
	if err != nil || len(query) < 2 {
		return errors.New("query must contain between 2 and 256 characters")
	}
	input.Query = query
	if input.Relation, err = graphString(input.Relation, "relation", 128); err != nil {
		return err
	}
	if !validPage(input.Limit) {
		return errors.New("limit must be between 1 and 100")
	}
	if len(input.Cursor) > 2048 || len(input.Kinds) > 3 {
		return errors.New("invalid candidate search")
	}
	seen := map[string]bool{}
	for _, kind := range input.Kinds {
		if seen[kind] || !oneOf(kind, "user", "group", "service_account") {
			return errors.New("invalid candidate kind")
		}
		seen[kind] = true
	}
	return nil
}

func validateCandidateSearchResult(result ResourceLinkCandidateSearchResult) error {
	if result.Candidates == nil {
		return errors.New("invalid candidate response")
	}
	if result.NextCursor != nil && (*result.NextCursor == "" || len(*result.NextCursor) > 2048) {
		return errors.New("invalid candidate cursor")
	}
	for _, item := range result.Candidates {
		if !oneOf(item.Kind, "user", "group", "service_account") || !oneOf(item.LinkState, "available", "linked", "pending_invitation") || item.DisplayName == "" {
			return errors.New("invalid candidate response")
		}
		if (item.Kind == "user" && item.Subject == "") ||
			(item.Kind == "group" && (item.Resource == "" || item.SubjectRelation != "member")) ||
			(item.Kind == "service_account" && (item.Resource == "" || item.SubjectRelation != "")) {
			return errors.New("invalid candidate response")
		}
	}
	return nil
}

func validateLinkChange(change ResourceLinkChange) error {
	if !oneOf(change.Action, "grant", "revoke") {
		return errors.New("invalid link action")
	}
	if (change.Action == "grant" && change.Relation == "") || (change.Action == "revoke" && change.LinkID == "" && change.Collaborator == "") {
		return errors.New("invalid link change target")
	}
	for name, item := range map[string]struct {
		value string
		max   int
	}{"link ID": {change.LinkID, 256}, "collaborator": {change.Collaborator, 512}, "relation": {change.Relation, 128}, "subject": {change.Subject, 512}, "email": {change.Email, 320}, "subject resource": {change.SubjectResource, 512}, "subject relation": {change.SubjectRelation, 128}} {
		if item.value != "" {
			if _, err := graphString(item.value, name, item.max); err != nil {
				return err
			}
		}
	}
	if (change.Provisioning != "" && !oneOf(change.Provisioning, "existing_only", "create_if_missing")) ||
		(change.Delivery != "" && !oneOf(change.Delivery, "email", "in_app", "external", "none", "notification_only")) {
		return errors.New("invalid link change mode")
	}
	return nil
}

func validateLinkEnvelope(envelope ResourceLinkEnvelopeSubmission) error {
	if envelope.EncryptionSuite != "X25519-HKDF-SHA256-AES-256-GCM" {
		return errors.New("invalid resource link envelope suite")
	}
	for name, item := range map[string]struct {
		value string
		max   int
	}{"manifest item ID": {envelope.ManifestItemID, 256}, "ciphertext": {envelope.Ciphertext, 65536}, "AAD hash": {envelope.AADHash, 128}, "issuer": {envelope.Issuer, 512}, "issuer key ID": {envelope.IssuerKeyID, 256}, "signature": {envelope.Signature, 256}} {
		if _, err := graphString(item.value, name, item.max); err != nil {
			return err
		}
	}
	return nil
}

func validateResourceLinkResult(result ResourceLinkResult, resource string) error {
	if result.Resource != resource || !oneOf(result.Status, "ready", "committing", "pending_acceptance", "pending_encryption", "active", "failed", "expired") || result.ExpiresAt < 0 || result.Outcomes == nil || result.InvitationActions == nil || result.KeyRequirements == nil || result.Impact.ImpactedResources == nil || result.Impact.RetainedResources == nil || result.Impact.RekeyResources == nil {
		return errors.New("invalid resource link response")
	}
	if !oneOf(result.Capacity.Scope, "per_organization", "per_account") || result.Capacity.Before < 0 || result.Capacity.After < 0 || result.Capacity.Claim < 0 || result.Capacity.Release < 0 || result.Billing.CurrentQuantity < 0 || result.Billing.NextCycleQuantity < 0 || result.Billing.Increase < 0 || result.Billing.NextCycleReduction < 0 {
		return errors.New("invalid resource link capacity")
	}
	for _, outcome := range result.Outcomes {
		if outcome.Resource == "" || outcome.Subject == "" || outcome.Relation == "" || !oneOf(outcome.State, "active", "pending_acceptance", "pending_encryption", "revoked", "denied") {
			return errors.New("invalid resource link outcome")
		}
	}
	for _, action := range result.InvitationActions {
		if action.InvitationID == "" || !oneOf(action.Action, "preserve", "claim", "activate", "supersede", "cancel") {
			return errors.New("invalid resource link invitation action")
		}
	}
	for _, item := range result.KeyRequirements {
		if item.ManifestItemID == "" || item.GrantID == "" || item.Resource == "" || item.Relation == "" || item.KeyResource == "" || item.KeyVersion == "" || item.RecipientSubject == "" || item.RecipientKeyID == "" || item.EncryptionAlgorithm != "X25519" || len(item.PublicKey) != 32 || (item.Activation != "" && !oneOf(item.Activation, "active_access", "pending_invitation")) {
			return errors.New("invalid resource link key requirement")
		}
	}
	return nil
}

func collaboratorQuery(options ResourceCollaboratorListOptions) (string, error) {
	if !validPage(options.Limit) {
		return "", errors.New("limit must be between 1 and 100")
	}
	query := url.Values{}
	for name, item := range map[string]struct {
		value string
		max   int
	}{"view": {options.View, 16}, "search": {options.Search, 256}, "email": {options.Email, 320}, "subject": {options.Subject, 512}, "resource_subject": {options.ResourceSubject, 640}, "via_group": {options.ViaGroup, 512}, "cursor": {options.Cursor, 2048}} {
		if item.value != "" {
			value, err := graphString(item.value, name, item.max)
			if err != nil {
				return "", err
			}
			query.Set(name, value)
		}
	}
	if options.View != "" && !oneOf(options.View, "direct", "effective") {
		return "", errors.New("invalid collaborator view")
	}
	if options.Direct != nil {
		query.Set("direct", strconv.FormatBool(*options.Direct))
	}
	for _, kind := range append(append([]string{}, options.Kind), options.Kinds...) {
		if kind == "" {
			continue
		}
		if !oneOf(kind, "user", "group", "service_account", "invitation") {
			return "", errors.New("invalid collaborator kind")
		}
		query.Add("kind", kind)
	}
	for _, status := range append(append([]string{}, options.Status), options.Statuses...) {
		if status == "" {
			continue
		}
		value, err := graphString(status, "status", 64)
		if err != nil {
			return "", err
		}
		query.Add("status", value)
	}
	for _, relation := range options.Relations {
		value, err := graphString(relation, "relation", 128)
		if err != nil {
			return "", err
		}
		query.Add("relation", value)
	}
	if options.Limit > 0 {
		query.Set("limit", strconv.Itoa(options.Limit))
	}
	if len(query) == 0 {
		return "", nil
	}
	return "?" + query.Encode(), nil
}

func validateCollaboratorList(result ResourceCollaboratorList, resource string) error {
	if result.Resource != resource || result.Collaborators == nil {
		return errors.New("invalid collaborator response")
	}
	if result.NextCursor != nil && (*result.NextCursor == "" || len(*result.NextCursor) > 2048) {
		return errors.New("invalid collaborator cursor")
	}
	for _, item := range result.Collaborators {
		if !oneOf(item.Kind, "user", "group", "service_account", "invitation") || item.ID == "" || item.Status == "" || item.Relations == nil {
			return errors.New("invalid collaborator response")
		}
		if item.Access != nil {
			if item.Access.Paths == nil {
				return errors.New("invalid collaborator access")
			}
			for _, path := range item.Access.Paths {
				if !oneOf(path.Type, "direct", "group") || path.Relation == "" || path.Via == nil {
					return errors.New("invalid collaborator access path")
				}
			}
		}
		if item.Recipient != nil && !oneOf(item.Recipient.Type, "user", "email", "group") {
			return errors.New("invalid collaborator recipient")
		}
	}
	return nil
}

func validateResourceSearch(input ResourceSearchInput) error {
	if input.Page != nil && (!validPage(input.Page.Limit) || len(input.Page.Cursor) > 2048) {
		return errors.New("invalid resource search page")
	}
	for _, include := range input.Include {
		if !oneOf(include, "parent", "collaborator_matches", "references") {
			return errors.New("invalid resource search include")
		}
	}
	if input.Sort != nil && ((input.Sort.Field != "" && !oneOf(input.Sort.Field, "display_name", "resource_type", "resource")) || (input.Sort.Direction != "" && !oneOf(input.Sort.Direction, "asc", "desc"))) {
		return errors.New("invalid resource search sort")
	}
	if input.Filters != nil && input.Filters.Resource != nil {
		filter := input.Filters.Resource
		for name, item := range map[string]struct {
			value string
			max   int
		}{"search": {filter.Search, 256}, "parent": {filter.Parent, 512}} {
			if item.value != "" {
				if _, err := graphString(item.value, name, item.max); err != nil {
					return err
				}
			}
		}
		for _, values := range []struct {
			name   string
			values []string
			max    int
		}{{name: "resource", max: 512, values: filter.Resources}, {name: "resource type", max: 128, values: filter.Types}, {name: "resource status", max: 64, values: filter.Statuses}} {
			for _, value := range values.values {
				if _, err := graphString(value, values.name, values.max); err != nil {
					return err
				}
			}
		}
		if len(filter.References) > 16 {
			return errors.New("resource references may contain at most 16 fields")
		}
		for field, target := range filter.References {
			if _, err := graphString(field, "reference field", 128); err != nil {
				return err
			}
			if _, err := graphString(target, "reference target", 512); err != nil {
				return err
			}
		}
	}
	if input.Filters != nil && input.Filters.Collaborator != nil {
		filter := input.Filters.Collaborator
		if filter.View != "" && !oneOf(filter.View, "direct", "effective") {
			return errors.New("invalid collaborator view")
		}
		for name, item := range map[string]struct {
			value string
			max   int
		}{"search": {filter.Search, 256}, "email": {filter.Email, 320}, "resource subject": {filter.ResourceSubject, 640}} {
			if item.value != "" {
				if _, err := graphString(item.value, name, item.max); err != nil {
					return err
				}
			}
		}
		for _, kind := range filter.Kinds {
			if !oneOf(kind, "user", "group", "service_account", "invitation") {
				return errors.New("invalid collaborator kind")
			}
		}
		for _, values := range []struct {
			name   string
			values []string
			max    int
		}{{name: "collaborator subject", max: 512, values: filter.Subjects}, {name: "collaborator relation", max: 128, values: filter.Relations}, {name: "collaborator status", max: 64, values: filter.Statuses}, {name: "collaborator via group", max: 512, values: filter.ViaGroups}} {
			for _, value := range values.values {
				if _, err := graphString(value, values.name, values.max); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateResourceSearchList(result ResourceSearchList) error {
	if result.Resources == nil {
		return errors.New("invalid resource search response")
	}
	if result.NextCursor != nil && (*result.NextCursor == "" || len(*result.NextCursor) > 2048) {
		return errors.New("invalid resource search cursor")
	}
	for _, item := range result.Resources {
		if item.Resource == "" || item.ResourceType == "" || item.DisplayName == "" || item.Status == "" {
			return errors.New("invalid resource search response")
		}
		if item.Parent != nil && (item.Parent.Resource == "" || item.Parent.ResourceType == "" || item.Parent.DisplayName == "") {
			return errors.New("invalid resource search parent")
		}
		for _, collaborator := range item.CollaboratorMatches {
			if !oneOf(collaborator.Kind, "user", "group", "service_account", "invitation") || collaborator.ID == "" {
				return errors.New("invalid resource search collaborator")
			}
		}
	}
	return nil
}
