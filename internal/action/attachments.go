package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/storage"
)

// --- Action definitions for attachment upload/delete ---

type attachmentUploadInput struct {
	TaskID    string `json:"task_id"`
	ProjectID string `json:"project_id"`
	Filename  string `json:"filename"`
	Data      []byte `json:"data"`
	MimeType  string `json:"mime_type"`
}

type attachmentDeleteInput struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	ProjectID string `json:"project_id"`
}

type attachmentUploadOutput struct {
	ID         string `json:"id"`
	Filename   string `json:"filename"`
	Mime       string `json:"mime"`
	Size       int64  `json:"size"`
	StorageKey string `json:"storage_key"`
	CreatedAt  string `json:"created_at"`
}

func init() {
	Register(Definition{
		Name:       "attachment.upload",
		Impact:     ImpactLow,
		Permission: "task.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAttachmentUpload,
	})

	Register(Definition{
		Name:       "attachment.delete",
		Impact:     ImpactLow,
		Permission: "task.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAttachmentDelete,
	})
}

// StoreProvider is the interface the action package uses to access the storage backend.
// Set via SetStorageStore before dispatch.
var attachmentStore storage.Store

// SetStorageStore sets the attachment store for the action handlers.
func SetStorageStore(s storage.Store) { attachmentStore = s }

func handleAttachmentUpload(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input attachmentUploadInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("attachment.upload: %w", err)
	}

	if attachmentStore == nil {
		return nil, fmt.Errorf("attachment.upload: storage not configured")
	}

	// Delegate to the store — it handles size/type validation and processing.
	id, storageKey, err := attachmentStore.Upload(ctx, input.Filename, input.Data, ac.Org, input.TaskID)
	if err != nil {
		return nil, fmt.Errorf("attachment.upload: %w", err)
	}

	// Write attachment row.
	row, err := ac.Tx.CreateAttachment(ctx, sqlc.CreateAttachmentParams{
		ID:         id,
		OrgID:      ac.Org,
		TaskID:     input.TaskID,
		UploaderID: ac.Actor.ID,
		Filename:   input.Filename,
		Mime:       input.MimeType,
		Size:       int64(len(input.Data)),
		StorageKey: storageKey,
	})
	if err != nil {
		return nil, fmt.Errorf("attachment.upload: %w", err)
	}

	return attachmentUploadOutput{
		ID:         row.ID,
		Filename:   row.Filename,
		Mime:       row.Mime,
		Size:       row.Size,
		StorageKey: row.StorageKey,
		CreatedAt:  row.CreatedAt,
	}, nil
}

func handleAttachmentDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input attachmentDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("attachment.delete: %w", err)
	}

	if attachmentStore == nil {
		return nil, fmt.Errorf("attachment.delete: storage not configured")
	}

	// Fetch attachment to verify ownership and get storage key.
	att, err := ac.Tx.GetAttachment(ctx, input.ID)
	if err != nil {
		return nil, fmt.Errorf("attachment.delete: attachment not found")
	}
	if att.UploaderID != ac.Actor.ID {
		return nil, fmt.Errorf("attachment.delete: forbidden — not the uploader")
	}

	// Delete from store.
	if err := attachmentStore.Delete(ctx, att.StorageKey); err != nil {
		return nil, fmt.Errorf("attachment.delete: %w", err)
	}

	// Delete row.
	if err := ac.Tx.DeleteAttachment(ctx, sqlc.DeleteAttachmentParams{
		ID:    input.ID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("attachment.delete: %w", err)
	}

	return map[string]any{"deleted": true}, nil
}
