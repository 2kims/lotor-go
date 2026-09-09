package browseradapter

import (
	"net/url"
	"slices"
	"strings"
)

// resourceRoute is a browser-only allowlist. Provisioning endpoints such as
// resource-types and application credential issuance are intentionally absent.
func resourceRoute(method, escapedPath string) bool {
	if escapedPath == prefix+"/resources" {
		return method == "POST"
	}
	if escapedPath == prefix+"/billing/checkout-sessions" || escapedPath == prefix+"/billing/portal-sessions" {
		return method == "POST"
	}
	if escapedPath == prefix+"/organizations" {
		return method == "GET" || method == "POST"
	}
	if escapedPath == prefix+"/resources/search" {
		return method == "POST"
	}
	if escapedPath == prefix+"/me/invitations" || escapedPath == prefix+"/me/resources" || escapedPath == prefix+"/me/catalogs" {
		return method == "GET"
	}
	if escapedPath == prefix+"/key-access/subject-keys" || escapedPath == prefix+"/key-access/resource-envelope" {
		return method == "GET" || method == "POST"
	}
	if escapedPath == prefix+"/me/encryption-actions" {
		return method == "GET"
	}
	parts := strings.Split(strings.TrimPrefix(escapedPath, prefix+"/"), "/")
	if !strings.HasPrefix(escapedPath, prefix+"/") || len(parts) < 2 {
		return false
	}
	value, err := url.PathUnescape(parts[1])
	if err != nil || len(value) > 512 || !validValue(value) || strings.ContainsAny(value, "/%\\?#") || value == "." || value == ".." {
		return false
	}
	if parts[0] == "operations" {
		return len(parts) == 2 && method == "GET"
	}
	if parts[0] == "me" && len(parts) == 4 && parts[1] == "catalogs" {
		return method == "GET" && parts[3] == "entries" && clientIDPattern.MatchString(parts[2])
	}
	if parts[0] == "catalogs" && method == "GET" {
		return (len(parts) == 3 && parts[2] == "entries") ||
			(len(parts) == 4 && parts[2] == "entries" && clientIDPattern.MatchString(parts[3]))
	}
	if parts[0] == "key-access" && len(parts) >= 3 {
		id, err := url.PathUnescape(parts[2])
		if err != nil || !clientIDPattern.MatchString(id) {
			return false
		}
		if parts[1] == "subject-keys" {
			return len(parts) == 3 && method == "DELETE"
		}
		if parts[1] == "claims" {
			return (len(parts) == 3 && method == "GET") || (len(parts) == 4 && method == "POST" && (parts[3] == "transfer" || parts[3] == "complete"))
		}
		return false
	}
	if parts[0] == "me" && len(parts) == 4 && parts[1] == "encryption-actions" {
		return clientIDPattern.MatchString(parts[2]) && parts[3] == "complete" && method == "POST"
	}
	if parts[0] == "me" && len(parts) == 4 && parts[1] == "invitations" {
		id, err := url.PathUnescape(parts[2])
		return err == nil && clientIDPattern.MatchString(id) && method == "POST" && (parts[3] == "accept" || parts[3] == "decline")
	}
	if parts[0] != "resources" {
		return false
	}
	if len(parts) == 2 {
		return method == "GET" || method == "PUT" || method == "DELETE"
	}
	if len(parts) == 3 && parts[2] == "collaborators" {
		return method == "GET"
	}
	if parts[2] == "scim-directories" {
		return (len(parts) == 3 && (method == "GET" || method == "POST")) ||
			(len(parts) == 4 && clientIDPattern.MatchString(parts[3]) && (method == "GET" || method == "PUT"))
	}
	if len(parts) == 3 && parts[2] == "catalog-binding" {
		return method == "PUT"
	}
	if parts[2] == "credentials" {
		return (len(parts) == 3 && (method == "GET" || method == "POST")) ||
			(len(parts) == 4 && method == "DELETE" && clientIDPattern.MatchString(parts[3])) ||
			(len(parts) == 5 && method == "POST" && clientIDPattern.MatchString(parts[3]) && parts[4] == "rotate")
	}
	if parts[2] == "payloads" && len(parts) >= 4 && clientIDPattern.MatchString(parts[3]) {
		return (len(parts) == 4 && (method == "GET" || method == "DELETE")) ||
			(len(parts) == 5 && method == "POST" && slices.Contains([]string{"uploads", "commits", "access", "rewraps"}, parts[4]))
	}
	if parts[2] == "executions" && len(parts) == 4 && (parts[3] == "preflight" || parts[3] == "commit") {
		return method == "POST"
	}
	if len(parts) == 3 && parts[2] == "e2ee" {
		return method == "GET" || method == "PUT"
	}
	if len(parts) >= 4 && parts[2] == "e2ee" && parts[3] == "function-bindings" {
		return (len(parts) == 4 && (method == "POST" || method == "GET")) ||
			(len(parts) == 5 && clientIDPattern.MatchString(parts[4]) && (method == "GET" || method == "DELETE")) ||
			(len(parts) == 6 && clientIDPattern.MatchString(parts[4]) && parts[5] == "challenge" && method == "POST")
	}
	if len(parts) == 4 {
		if parts[2] == "link-candidates" && parts[3] == "search" {
			return method == "POST"
		}
		if parts[2] == "links" {
			if parts[3] == "preflight" || parts[3] == "commit" {
				return method == "POST"
			}
			return method == "DELETE" && clientIDPattern.MatchString(parts[3])
		}
	}
	return len(parts) == 3 && method == "POST" && (parts[2] == "move" || parts[2] == "disable" || parts[2] == "restore")
}

func validResourceQuery(method, path, raw string) bool {
	if raw == "" {
		return true
	}
	if method != "GET" || len(raw) > 8192 {
		return false
	}
	allowed := ""
	switch {
	case path == prefix+"/key-access/resource-envelope":
		allowed = " resource "
	case path == prefix+"/me/invitations":
		allowed = " cursor limit "
	case path == prefix+"/me/catalogs" || strings.HasPrefix(path, prefix+"/me/catalogs/"):
		allowed = " cursor limit "
	case path == prefix+"/me/resources":
		allowed = " cursor limit type access_state parent "
	case strings.HasPrefix(path, prefix+"/catalogs/"):
		allowed = " resource cursor limit "
	case strings.HasSuffix(path, "/collaborators"):
		allowed = " view search email subject resource_subject via_group direct kind status relation cursor limit "
	case strings.HasPrefix(path, prefix+"/resources/") && strings.HasSuffix(path, "/scim-directories"):
		allowed = " cursor limit "
	default:
		return false
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return false
	}
	for key, values := range query {
		if !slices.Contains(strings.Fields(allowed), key) {
			return false
		}
		if len(values) > 1 && key != "type" && key != "access_state" && key != "kind" && key != "status" && key != "relation" {
			return false
		}
	}
	return true
}
