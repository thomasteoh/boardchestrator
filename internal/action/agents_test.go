package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

func TestAgentCreateAndList(t *testing.T) {
	ctx := context.Background()
	db := dbtest.New(t)

	d := New(db)

	// Seed org
	orgInput := map[string]string{"name": "test-org"}
	raw, _ := json.Marshal(orgInput)
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create", raw, Opts{})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID := orgResult.(map[string]string)["id"]

	// Seed provider
	provInput := map[string]any{
		"kind":     "openai-compatible",
		"name":     "Test Provider",
		"base_url": "https://test.example.com/v1",
		"models":   []string{"gpt-4o"},
	}
	raw2, _ := json.Marshal(provInput)
	provResult, err := d.Dispatch(ctx, userActor(), "provider.create", raw2, Opts{})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	providerID := provResult.(map[string]string)["id"]

	// Create an agent
	input := map[string]any{
		"org_id":      orgID,
		"name":        "test-agent",
		"provider_id": providerID,
		"model":       "gpt-4o",
	}
	raw3, _ := json.Marshal(input)
	result, err := d.Dispatch(ctx, userActor(), "agent.create", raw3, Opts{})
	if err != nil {
		t.Fatalf("agent.create: %v", err)
	}
	id := result.(map[string]string)["id"]
	if id == "" {
		t.Fatal("expected non-empty agent id")
	}

	// List agents by org
	listInput := map[string]string{"org_id": orgID}
	raw4, _ := json.Marshal(listInput)
	listResult, err := d.Dispatch(ctx, userActor(), "agent.list", raw4, Opts{})
	if err != nil {
		t.Fatalf("agent.list: %v", err)
	}
	agents := listResult.([]sqlc.Agent)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Name != "test-agent" {
		t.Fatalf("expected name test-agent, got %s", agents[0].Name)
	}

	// Delete agent
	deleteInput := map[string]string{"id": id}
	raw5, _ := json.Marshal(deleteInput)
	_, err = d.Dispatch(ctx, userActor(), "agent.delete", raw5, Opts{})
	if err != nil {
		t.Fatalf("agent.delete: %v", err)
	}
}

func TestAgentDuplicateNameRejected(t *testing.T) {
	ctx := context.Background()
	db := dbtest.New(t)

	d := New(db)

	// Seed org
	orgInput := map[string]string{"name": "dup-org"}
	raw, _ := json.Marshal(orgInput)
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create", raw, Opts{})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID := orgResult.(map[string]string)["id"]

	// Seed provider
	provInput := map[string]any{
		"kind":     "openai-compatible",
		"name":     "Dup Provider",
		"base_url": "https://test.example.com/v1",
		"models":   []string{"gpt-4o"},
	}
	raw2, _ := json.Marshal(provInput)
	provResult, err := d.Dispatch(ctx, userActor(), "provider.create", raw2, Opts{})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	providerID := provResult.(map[string]string)["id"]

	input := map[string]any{
		"org_id":      orgID,
		"name":        "dup-agent",
		"provider_id": providerID,
		"model":       "gpt-4o",
	}
	raw3, _ := json.Marshal(input)
	_, err = d.Dispatch(ctx, userActor(), "agent.create", raw3, Opts{})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = d.Dispatch(ctx, userActor(), "agent.create", raw3, Opts{})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestAgentListTemplates(t *testing.T) {
	ctx := context.Background()
	db := dbtest.New(t)

	d := New(db)

	// Seed org
	orgInput := map[string]string{"name": "tmpl-org"}
	raw, _ := json.Marshal(orgInput)
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create", raw, Opts{})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID := orgResult.(map[string]string)["id"]

	// Seed provider
	provInput := map[string]any{
		"kind":     "openai-compatible",
		"name":     "Template Provider",
		"base_url": "https://test.example.com/v1",
		"models":   []string{"gpt-4o"},
	}
	raw2, _ := json.Marshal(provInput)
	provResult, err := d.Dispatch(ctx, userActor(), "provider.create", raw2, Opts{})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	providerID := provResult.(map[string]string)["id"]

	// Create a platform template (org_id empty = platform)
	input := map[string]any{
		"org_id":      "",
		"name":        "template-agent",
		"provider_id": providerID,
		"model":       "gpt-4o",
	}
	raw3, _ := json.Marshal(input)
	_, err = d.Dispatch(ctx, userActor(), "agent.create", raw3, Opts{})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}

	// Create an org agent
	input2 := map[string]any{
		"org_id":      orgID,
		"name":        "org-agent",
		"provider_id": providerID,
		"model":       "claude-3",
	}
	raw4, _ := json.Marshal(input2)
	_, err = d.Dispatch(ctx, userActor(), "agent.create", raw4, Opts{})
	if err != nil {
		t.Fatalf("create org agent: %v", err)
	}

	// List templates should only return platform agents
	result, err := d.Dispatch(ctx, userActor(), "agent.list-templates", json.RawMessage("{}"), Opts{})
	if err != nil {
		t.Fatalf("agent.list-templates: %v", err)
	}
	templates := result.([]sqlc.Agent)
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].Name != "template-agent" {
		t.Fatalf("expected template-agent, got %s", templates[0].Name)
	}
}
