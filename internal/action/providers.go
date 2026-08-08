package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for LLM providers (WU-302) ---

type providerCreateInput struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	BaseURL string   `json:"base_url"`
	Models  []string `json:"models"`
}

type providerUpdateInput struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	BaseURL string   `json:"base_url"`
	Models  []string `json:"models"`
}

type providerDeleteInput struct {
	ID string `json:"id"`
}

type providerOrgAllocateInput struct {
	ProviderID string `json:"provider_id"`
	OrgID      string `json:"org_id"`
}

type providerOrgDeallocateInput struct {
	ProviderID string `json:"provider_id"`
	OrgID      string `json:"org_id"`
}

type providerOrgListInput struct {
	OrgID string `json:"org_id"`
}

func init() {
	Register(Definition{
		Name:       "provider.create",
		Impact:     ImpactHigh,
		Permission: "provider.create",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderCreate,
	})
	Register(Definition{
		Name:       "provider.update",
		Impact:     ImpactHigh,
		Permission: "provider.update",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderUpdate,
	})
	Register(Definition{
		Name:       "provider.delete",
		Impact:     ImpactHigh,
		Permission: "provider.delete",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderDelete,
	})
	Register(Definition{
		Name:       "provider.list",
		Impact:     ImpactRead,
		Permission: "provider.list",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderList,
	})
	Register(Definition{
		Name:       "provider-org.allocate",
		Impact:     ImpactHigh,
		Permission: "provider.allocate",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderOrgAllocate,
	})
	Register(Definition{
		Name:       "provider-org.deallocate",
		Impact:     ImpactHigh,
		Permission: "provider.deallocate",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderOrgDeallocate,
	})
	Register(Definition{
		Name:       "provider-org.list",
		Impact:     ImpactRead,
		Permission: "provider-org.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProviderOrgList,
	})
}

// RegisterProviderActions is exported so cmd/bc/serve.go can ensure this init runs.
func RegisterProviderActions() {}

func handleProviderCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input providerCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("provider.create: %w", err)
	}
	modelsJSON, err := json.Marshal(input.Models)
	if err != nil {
		return nil, fmt.Errorf("provider.create: marshal models: %w", err)
	}
	id := newID()
	// key_enc is nullable — providers without auth (e.g. local endpoints) are valid.
	_, err = ac.Tx.CreateProvider(ctx, sqlc.CreateProviderParams{
		ID:         id,
		Kind:       input.Kind,
		Name:       input.Name,
		BaseUrl:    input.BaseURL,
		KeyEnc:     nil,
		ModelsJson: string(modelsJSON),
	})
	if err != nil {
		return nil, fmt.Errorf("provider.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleProviderUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input providerUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("provider.update: %w", err)
	}
	modelsJSON, err := json.Marshal(input.Models)
	if err != nil {
		return nil, fmt.Errorf("provider.update: marshal models: %w", err)
	}
	_, err = ac.Tx.UpdateProvider(ctx, sqlc.UpdateProviderParams{
		Kind:       input.Kind,
		Name:       input.Name,
		BaseUrl:    input.BaseURL,
		KeyEnc:     nil,
		ModelsJson: string(modelsJSON),
		ID:         input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("provider.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleProviderDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input providerDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("provider.delete: %w", err)
	}
	if err := ac.Tx.DeleteProvider(ctx, input.ID); err != nil {
		return nil, fmt.Errorf("provider.delete: %w", err)
	}
	return nil, nil
}

func handleProviderList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	providers, err := ac.Tx.ListProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("provider.list: %w", err)
	}
	return providers, nil
}

func handleProviderOrgAllocate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input providerOrgAllocateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("provider-org.allocate: %w", err)
	}
	id := newID()
	_, err := ac.Tx.CreateProviderOrg(ctx, sqlc.CreateProviderOrgParams{
		ID:         id,
		ProviderID: input.ProviderID,
		OrgID:      input.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("provider-org.allocate: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleProviderOrgDeallocate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input providerOrgDeallocateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("provider-org.deallocate: %w", err)
	}
	if err := ac.Tx.DeleteProviderOrg(ctx, sqlc.DeleteProviderOrgParams{
		ProviderID: input.ProviderID,
		OrgID:      input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("provider-org.deallocate: %w", err)
	}
	return nil, nil
}

func handleProviderOrgList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input providerOrgListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("provider-org.list: %w", err)
	}
	providers, err := ac.Tx.ListProviderOrgsByOrg(ctx, input.OrgID)
	if err != nil {
		return nil, fmt.Errorf("provider-org.list: %w", err)
	}
	return providers, nil
}
