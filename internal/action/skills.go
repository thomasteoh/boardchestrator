package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// McpEndpoint is a single external MCP tool endpoint attached to a skill.
// Credentials are encrypted at rest (mcp_endpoints_enc) using the dispatcher's
// secret key (SPEC §10: SSRF-validated URLs + encrypted creds).
type McpEndpoint struct {
	URL          string            `json:"url"`
	Name         string            `json:"name"`
	AuthToken    string            `json:"auth_token,omitempty"`
	AuthType     string            `json:"auth_type,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

type skillCreateInput struct {
	OrgID          string        `json:"org_id"` // "" = platform skill
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Instructions   string        `json:"instructions"`
	AllowedActions []string      `json:"allowed_actions"`
	ParamSchema    string        `json:"param_schema"`
	McpEndpoints   []McpEndpoint `json:"mcp_endpoints,omitempty"`
}

type skillUpdateInput struct {
	ID             string        `json:"id"`
	OrgID          string        `json:"org_id"`
	Description    string        `json:"description"`
	Instructions   string        `json:"instructions"`
	AllowedActions []string      `json:"allowed_actions"`
	ParamSchema    string        `json:"param_schema"`
	McpEndpoints   []McpEndpoint `json:"mcp_endpoints,omitempty"`
}

type skillDeleteInput struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
}

type skillListInput struct {
	OrgID string `json:"org_id"`
}

type skillLatestInput struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

type skillImportInput struct {
	OrgID  string      `json:"org_id"`
	Bundle SkillBundle `json:"bundle"`
}

// SkillBundle is the import/export JSON bundle (SPEC §10 import/export).
type SkillBundle struct {
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Instructions   string        `json:"instructions"`
	AllowedActions []string      `json:"allowed_actions"`
	ParamSchema    string        `json:"param_schema"`
	McpEndpoints   []McpEndpoint `json:"mcp_endpoints,omitempty"`
	Version        int           `json:"version,omitempty"` // imported at this version (or next free if 0)
}

func init() {
	Register(Definition{
		Name:       "skill.create",
		Impact:     ImpactHigh,
		Permission: "skill.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillCreate,
	})
	Register(Definition{
		Name:       "skill.update",
		Impact:     ImpactHigh,
		Permission: "skill.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillUpdate,
	})
	Register(Definition{
		Name:       "skill.delete",
		Impact:     ImpactHigh,
		Permission: "skill.delete",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillDelete,
	})
	Register(Definition{
		Name:       "skill.list",
		Impact:     ImpactRead,
		Permission: "skill.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillList,
	})
	Register(Definition{
		Name:       "skill.list-platform",
		Impact:     ImpactRead,
		Permission: "skill.list",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillListPlatform,
	})
	Register(Definition{
		Name:       "skill.latest",
		Impact:     ImpactRead,
		Permission: "skill.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillLatest,
	})
	Register(Definition{
		Name:       "skill.import",
		Impact:     ImpactHigh,
		Permission: "skill.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillImport,
	})
	Register(Definition{
		Name:       "skill.export",
		Impact:     ImpactRead,
		Permission: "skill.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSkillExport,
	})
}

// RegisterSkillActions is a no-op marker; skills actions register in init().

// jsonString marshals v to a JSON string, returning "[]"/"{}" on error
// (never fails for the simple slices/maps skills handlers pass).
func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// validateAllowedActions verifies every allowed action is a registered action
// (SPEC §10 AC: allowed-actions must be a subset of the registry).
func validateAllowedActions(actions []string) error {
	registered := make(map[string]bool)
	for _, d := range All() {
		registered[d.Name] = true
	}
	for _, a := range actions {
		if !registered[a] {
			return fmt.Errorf("allowed action %q is not in the action registry", a)
		}
	}
	return nil
}

// validateParamSchema verifies the param schema is valid JSON (may be empty).
func validateParamSchema(s string) error {
	if s == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return fmt.Errorf("param_schema must be valid JSON: %w", err)
	}
	return nil
}

// validateMcpEndpoints SSRF-validates each endpoint URL (SPEC §10).
func validateMcpEndpoints(eps []McpEndpoint) error {
	for _, ep := range eps {
		if ep.URL == "" {
			continue
		}
		if err := validateMcpEndpointURL(ep.URL); err != nil {
			return err
		}
	}
	return nil
}

// encryptMcpEndpoints serialises endpoints to JSON and encrypts with the
// dispatcher secret key. With no secret configured (test/dev), stores the
// plaintext JSON (not encrypted) so dev flows still work.
func encryptMcpEndpoints(ac ActionCtx, eps []McpEndpoint) (string, error) {
	if len(eps) == 0 {
		return "", nil
	}
	// gosec G117 flags McpEndpoint.AuthToken reaching json.Marshal. This is
	// the marshal step immediately before encryption below; the plaintext JSON
	// is returned only when no secret key is configured, which config.Load
	// forbids in production (BC_SECRET_KEY is required).
	b, err := json.Marshal(eps) //nolint:gosec // marshalled solely as input to Seal below
	if err != nil {
		return "", fmt.Errorf("encrypt endpoints: marshal: %w", err)
	}
	if len(ac.SecretKey) == 0 {
		return string(b), nil
	}
	enc, err := tenant.Encrypt(ac.SecretKey, string(b))
	if err != nil {
		return "", fmt.Errorf("encrypt endpoints: %w", err)
	}
	return enc, nil
}

// decryptMcpEndpoints returns the endpoints JSON as-is if it looks like
// plaintext JSON, otherwise decrypts with the secret key.
func decryptMcpEndpoints(ac ActionCtx, enc string) string {
	if enc == "" {
		return "[]"
	}
	// Plaintext JSON (dev/test, no secret) round-trips as valid JSON.
	if json.Valid([]byte(enc)) {
		return enc
	}
	if len(ac.SecretKey) == 0 {
		return "[]"
	}
	plain, err := tenant.Decrypt(ac.SecretKey, enc)
	if err != nil {
		return "[]"
	}
	return plain
}

func handleSkillCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.create: %w", err)
	}
	if input.Name == "" {
		return nil, fmt.Errorf("skill.create: name is required")
	}
	if err := validateAllowedActions(input.AllowedActions); err != nil {
		return nil, fmt.Errorf("skill.create: %w", err)
	}
	if err := validateParamSchema(input.ParamSchema); err != nil {
		return nil, fmt.Errorf("skill.create: %w", err)
	}
	if err := validateMcpEndpoints(input.McpEndpoints); err != nil {
		return nil, fmt.Errorf("skill.create: %w", err)
	}
	enc, err := encryptMcpEndpoints(ac, input.McpEndpoints)
	if err != nil {
		return nil, fmt.Errorf("skill.create: %w", err)
	}
	id := newID()
	_, err = ac.Tx.CreateSkill(ctx, sqlc.CreateSkillParams{
		ID:                 id,
		OrgID:              sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:               input.Name,
		Description:        input.Description,
		Instructions:       input.Instructions,
		AllowedActionsJson: jsonString(input.AllowedActions),
		ParamSchemaJson:    input.ParamSchema,
		McpEndpointsEnc:    enc,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.create: %w", err)
	}
	return map[string]string{"id": id, "version": "1"}, nil
}

func handleSkillUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}
	if err := validateAllowedActions(input.AllowedActions); err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}
	if err := validateParamSchema(input.ParamSchema); err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}
	if err := validateMcpEndpoints(input.McpEndpoints); err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}
	enc, err := encryptMcpEndpoints(ac, input.McpEndpoints)
	if err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}

	// Load the source skill (org-scoped) to inherit its name + compute the next
	// version. A no-match (not this org) is a silent no-op, per convention.
	src, err := ac.Tx.FindSkillByIDAndOrg(ctx, sqlc.FindSkillByIDAndOrgParams{
		ID:    input.ID,
		OrgID: sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}

	maxV, err := ac.Tx.FindMaxSkillVersion(ctx, sqlc.FindMaxSkillVersionParams{
		OrgID: sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:  src.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}
	nextVer := maxV + 1

	id := newID()
	row, err := ac.Tx.CreateSkillAtVersion(ctx, sqlc.CreateSkillAtVersionParams{
		ID:                 id,
		OrgID:              sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:               src.Name,
		Version:            nextVer,
		Description:        input.Description,
		Instructions:       input.Instructions,
		AllowedActionsJson: jsonString(input.AllowedActions),
		ParamSchemaJson:    input.ParamSchema,
		McpEndpointsEnc:    enc,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.update: %w", err)
	}
	return map[string]string{"id": row.ID, "version": fmt.Sprintf("%d", row.Version)}, nil
}

func handleSkillDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.delete: %w", err)
	}
	if err := ac.Tx.DeleteSkill(ctx, sqlc.DeleteSkillParams{
		ID:    input.ID,
		OrgID: sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
	}); err != nil {
		return nil, fmt.Errorf("skill.delete: %w", err)
	}
	return nil, nil
}

func handleSkillList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.list: %w", err)
	}
	skills, err := ac.Tx.ListSkills(ctx, sql.NullString{String: input.OrgID, Valid: input.OrgID != ""})
	if err != nil {
		return nil, fmt.Errorf("skill.list: %w", err)
	}
	// Return latest version per name (agents pin latest by default).
	return latestSkills(skills), nil
}

func handleSkillListPlatform(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	skills, err := ac.Tx.ListPlatformSkills(ctx)
	if err != nil {
		return nil, fmt.Errorf("skill.list-platform: %w", err)
	}
	return latestSkills(skills), nil
}

func handleSkillLatest(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillLatestInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.latest: %w", err)
	}
	row, err := ac.Tx.FindLatestSkillByName(ctx, sqlc.FindLatestSkillByNameParams{
		OrgID: sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:  input.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.latest: %w", err)
	}
	return map[string]string{"id": row.ID, "version": fmt.Sprintf("%d", row.Version)}, nil
}

func handleSkillImport(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillImportInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}
	b := input.Bundle
	if b.Name == "" {
		return nil, fmt.Errorf("skill.import: bundle name is required")
	}
	if err := validateAllowedActions(b.AllowedActions); err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}
	if err := validateParamSchema(b.ParamSchema); err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}
	if err := validateMcpEndpoints(b.McpEndpoints); err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}
	enc, err := encryptMcpEndpoints(ac, b.McpEndpoints)
	if err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}

	// Determine the next free version for the name.
	version := int64(1)
	if b.Version > 0 {
		version = int64(b.Version)
	}
	maxV, err := ac.Tx.FindMaxSkillVersion(ctx, sqlc.FindMaxSkillVersionParams{
		OrgID: sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:  b.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}
	// If the requested version collides, bump to the next free one.
	if version <= maxV {
		version = maxV + 1
	}

	id := newID()
	_, err = ac.Tx.CreateSkillAtVersion(ctx, sqlc.CreateSkillAtVersionParams{
		ID:                 id,
		OrgID:              sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:               b.Name,
		Version:            version,
		Description:        b.Description,
		Instructions:       b.Instructions,
		AllowedActionsJson: jsonString(b.AllowedActions),
		ParamSchemaJson:    b.ParamSchema,
		McpEndpointsEnc:    enc,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.import: %w", err)
	}
	return map[string]string{"id": id, "version": fmt.Sprintf("%d", version)}, nil
}

func handleSkillExport(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input skillLatestInput // reuse: org_id + name
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("skill.export: %w", err)
	}
	row, err := ac.Tx.FindLatestSkillByName(ctx, sqlc.FindLatestSkillByNameParams{
		OrgID: sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		Name:  input.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("skill.export: %w", err)
	}
	var actions []string
	if err := json.Unmarshal([]byte(row.AllowedActionsJson), &actions); err != nil {
		actions = nil
	}
	bundle := SkillBundle{
		Name:           row.Name,
		Description:    row.Description,
		Instructions:   row.Instructions,
		AllowedActions: actions,
		ParamSchema:    row.ParamSchemaJson,
		Version:        int(row.Version),
	}
	// Decrypt endpoints for export.
	var eps []McpEndpoint
	dec := decryptMcpEndpoints(ac, row.McpEndpointsEnc)
	if json.Valid([]byte(dec)) {
		_ = json.Unmarshal([]byte(dec), &eps)
	}
	bundle.McpEndpoints = eps
	return bundle, nil
}

// latestSkills returns only the highest version of each skill name.
func latestSkills(skills []sqlc.Skill) []sqlc.Skill {
	best := map[string]sqlc.Skill{}
	for _, s := range skills {
		key := s.Name
		if cur, ok := best[key]; !ok || s.Version > cur.Version {
			best[key] = s
		}
	}
	out := make([]sqlc.Skill, 0, len(best))
	for _, s := range best {
		out = append(out, s)
	}
	return out
}
