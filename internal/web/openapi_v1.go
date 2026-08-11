package web

import (
	"encoding/json"
	"net/http"
)

// WU-402 OpenAPI: an OpenAPI 3.1 document describing the v1 RPC + resource
// routes, served at /api/v1/openapi.json, plus an embedded docs viewer page
// at /app/docs that renders the spec.

// openapiV1 is the OpenAPI 3.1 document (hand-built, stable).
var openapiV1 = map[string]any{
	"openapi": "3.1.0",
	"info": map[string]any{
		"title":       "Boardchestrator API",
		"version":     "1.0.0",
		"description": "Uniform action RPC + resource routes over /api/v1.",
	},
	"servers": []map[string]any{{"url": "/api/v1"}},
	"paths": map[string]any{
		"/actions/{name}": map[string]any{
			"post": map[string]any{
				"summary":     "Dispatch a registered action",
				"operationId": "dispatchAction",
				"parameters": []map[string]any{{
					"name": "name", "in": "path", "required": true, "schema": map[string]any{"type": "string"},
				}},
				"requestBody": map[string]any{
					"required": true,
					"content":  map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}},
				},
				"responses": map[string]any{
					"200": map[string]any{"description": "Action result", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}},
					"401": problemResp("unauthorized"),
					"429": problemResp("rate_limited"),
				},
			},
		},
		"/orgs/{orgID}/projects": map[string]any{
			"get": map[string]any{
				"summary":     "List projects in an org (cursor paginated)",
				"operationId": "listProjects",
				"parameters": []map[string]any{
					pathParam("orgID"),
					queryParam("cursor"),
					queryParam("limit"),
				},
				"responses": map[string]any{"200": map[string]any{"description": "Projects"}},
			},
		},
		"/orgs/{orgID}/projects/{projectKey}/tasks/{taskKey}": map[string]any{
			"get": map[string]any{
				"summary":     "Get a task by KEY-n alias",
				"operationId": "getTaskByKey",
				"parameters": []map[string]any{
					pathParam("orgID"), pathParam("projectKey"), pathParam("taskKey"),
				},
				"responses": map[string]any{"200": map[string]any{"description": "Task"}},
			},
		},
		"/orgs/{orgID}/projects/{projectID}/tasks/{taskID}": map[string]any{
			"put": map[string]any{
				"summary":     "Update a task (ETag/If-Match guarded)",
				"operationId": "updateTask",
				"parameters": []map[string]any{
					pathParam("orgID"), pathParam("projectID"), pathParam("taskID"),
					{"name": "If-Match", "in": "header", "required": false, "schema": map[string]any{"type": "string"}},
				},
				"responses": map[string]any{
					"200": map[string]any{"description": "Updated task"},
					"412": problemResp("conflict"),
				},
			},
		},
		"/orgs/{orgID}/projects/{projectID}/tasks/{taskID}/comments": map[string]any{
			"get": map[string]any{
				"summary":     "List comments on a task",
				"operationId": "listComments",
				"parameters":  []map[string]any{pathParam("orgID"), pathParam("projectID"), pathParam("taskID")},
				"responses":   map[string]any{"200": map[string]any{"description": "Comments"}},
			},
		},
		"/orgs/{orgID}/projects/{projectID}/sprints": map[string]any{
			"get": map[string]any{
				"summary":     "List sprints for a project",
				"operationId": "listSprints",
				"parameters":  []map[string]any{pathParam("orgID"), pathParam("projectID")},
				"responses":   map[string]any{"200": map[string]any{"description": "Sprints"}},
			},
		},
		"/orgs/{orgID}/labels": map[string]any{
			"get": map[string]any{
				"summary":     "List labels in an org",
				"operationId": "listLabels",
				"parameters":  []map[string]any{pathParam("orgID")},
				"responses":   map[string]any{"200": map[string]any{"description": "Labels"}},
			},
		},
		"/orgs/{orgID}/search": map[string]any{
			"get": map[string]any{
				"summary":     "Search tasks, projects, comments",
				"operationId": "search",
				"parameters":  []map[string]any{pathParam("orgID"), queryParam("q")},
				"responses":   map[string]any{"200": map[string]any{"description": "Search results"}},
			},
		},
	},
	"components": map[string]any{
		"securitySchemes": map[string]any{
			"BearerAuth": map[string]any{"type": "http", "scheme": "bearer"},
		},
		"schemas": map[string]any{
			"Problem": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"type":   map[string]any{"type": "string"},
					"title":  map[string]any{"type": "string"},
					"status": map[string]any{"type": "integer"},
					"detail": map[string]any{"type": "string"},
				},
			},
		},
	},
	"security": []map[string]any{{"BearerAuth": []any{}}},
}

// problemResp builds a problem+json response entry for a stable code.
func problemResp(code string) map[string]any {
	return map[string]any{
		"description": code,
		"content": map[string]any{
			"application/problem+json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Problem"}},
		},
	}
}

// pathParam/queryParam build OpenAPI parameter entries.
func pathParam(name string) map[string]any {
	return map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]any{"type": "string"}}
}

func queryParam(name string) map[string]any {
	return map[string]any{"name": name, "in": "query", "required": false, "schema": map[string]any{"type": "string"}}
}

// handleOpenAPI serves the OpenAPI 3.1 document (WU-402 AC).
func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(openapiV1)
}

// handleDocsPage renders the embedded OpenAPI docs viewer (WU-402 AC).
func handleDocsPage(w http.ResponseWriter, r *http.Request) {
	// Minimal embedded viewer: load the spec into a pre-formatted block.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	b, _ := json.MarshalIndent(openapiV1, "", "  ")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Boardchestrator API docs</title></head>
<body><h1>Boardchestrator API — OpenAPI 3.1</h1>
<p>Spec: <a href="/api/v1/openapi.json">/api/v1/openapi.json</a></p>
<pre style="white-space:pre-wrap">` + string(b) + `</pre></body></html>`))
}
