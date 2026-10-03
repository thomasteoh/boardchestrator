package scim

import "net/http"

// Schema URNs (RFC 7643, RFC 7644).
const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError          = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaSPConfig       = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType   = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema         = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// MaxResults is the most resources one list response returns.
const MaxResults = 200

// serviceProviderConfig is GET /ServiceProviderConfig (RFC 7643 §5).
func (h *Handler) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":          []string{SchemaSPConfig},
		"documentationUri": "",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": MaxResults},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token",
			"description": "A SCIM token issued under Organisation settings, Single sign-on, SCIM provisioning.",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": h.base + "/ServiceProviderConfig"},
	})
}

func (h *Handler) resourceTypeUser() map[string]any {
	return map[string]any{
		"schemas": []string{SchemaResourceType}, "id": "User", "name": "User", "endpoint": "/Users",
		"description": "User account", "schema": SchemaUser,
		"schemaExtensions": []map[string]any{{"schema": SchemaEnterpriseUser, "required": false}},
		"meta":             map[string]any{"resourceType": "ResourceType", "location": h.base + "/ResourceTypes/User"},
	}
}

func (h *Handler) resourceTypeGroup() map[string]any {
	return map[string]any{
		"schemas": []string{SchemaResourceType}, "id": "Group", "name": "Group", "endpoint": "/Groups",
		"description": "Group", "schema": SchemaGroup,
		"meta": map[string]any{"resourceType": "ResourceType", "location": h.base + "/ResourceTypes/Group"},
	}
}

// resourceTypes is GET /ResourceTypes[/{id}].
func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	all := []map[string]any{h.resourceTypeUser(), h.resourceTypeGroup()}
	if id := r.PathValue("id"); id != "" {
		for _, rt := range all {
			if rt["id"] == id {
				writeJSON(w, http.StatusOK, rt)
				return
			}
		}
		writeError(w, http.StatusNotFound, "", "Resource type not found.")
		return
	}
	writeList(w, len(all), 1, all)
}

func attr(name, typ string, required bool, mutability, returned, uniqueness string, caseExact bool) map[string]any {
	return map[string]any{
		"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": caseExact,
		"mutability": mutability, "returned": returned, "uniqueness": uniqueness,
	}
}

func (h *Handler) userSchema() map[string]any {
	name := attr("name", "complex", false, "readWrite", "default", "none", false)
	name["subAttributes"] = []map[string]any{
		attr("formatted", "string", false, "readWrite", "default", "none", false),
		attr("familyName", "string", false, "readWrite", "default", "none", false),
		attr("givenName", "string", false, "readWrite", "default", "none", false),
	}
	emails := attr("emails", "complex", false, "readWrite", "default", "none", false)
	emails["multiValued"] = true
	emails["subAttributes"] = []map[string]any{
		attr("value", "string", false, "readWrite", "default", "none", false),
		attr("type", "string", false, "readWrite", "default", "none", false),
		attr("primary", "boolean", false, "readWrite", "default", "none", false),
	}
	return map[string]any{
		"schemas": []string{SchemaSchema}, "id": SchemaUser, "name": "User", "description": "User account",
		"attributes": []map[string]any{
			attr("userName", "string", true, "readWrite", "default", "server", false),
			name,
			attr("displayName", "string", false, "readWrite", "default", "none", false),
			emails,
			attr("active", "boolean", false, "readWrite", "default", "none", false),
			attr("externalId", "string", false, "readWrite", "default", "none", true),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.base + "/Schemas/" + SchemaUser},
	}
}

func (h *Handler) groupSchema() map[string]any {
	members := attr("members", "complex", false, "readWrite", "default", "none", false)
	members["multiValued"] = true
	members["subAttributes"] = []map[string]any{
		attr("value", "string", false, "immutable", "default", "none", true),
		attr("display", "string", false, "readOnly", "default", "none", false),
	}
	return map[string]any{
		"schemas": []string{SchemaSchema}, "id": SchemaGroup, "name": "Group", "description": "Group",
		"attributes": []map[string]any{
			attr("displayName", "string", true, "readWrite", "default", "none", false),
			members,
			attr("externalId", "string", false, "readWrite", "default", "none", true),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.base + "/Schemas/" + SchemaGroup},
	}
}

// schemas is GET /Schemas[/{id}].
func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	all := []map[string]any{h.userSchema(), h.groupSchema()}
	if id := r.PathValue("id"); id != "" {
		for _, s := range all {
			if s["id"] == id {
				writeJSON(w, http.StatusOK, s)
				return
			}
		}
		writeError(w, http.StatusNotFound, "", "Schema not found.")
		return
	}
	writeList(w, len(all), 1, all)
}
