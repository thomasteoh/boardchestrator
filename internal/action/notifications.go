package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type markReadInput struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
}

type markAllReadInput struct {
	UserID string `json:"user_id"`
}

func init() {
	Register(Definition{
		Name:       "notif.mark_read",
		Impact:     ImpactLow,
		Permission: "notif.mark_read",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleMarkRead,
	})
	Register(Definition{
		Name:       "notif.mark_all_read",
		Impact:     ImpactLow,
		Permission: "notif.mark_all_read",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleMarkAllRead,
	})
	Register(Definition{
		Name:       "notif.list",
		Impact:     ImpactRead,
		Permission: "notif.list",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleNotifList,
	})
	Register(Definition{
		Name:       "notif.unread_count",
		Impact:     ImpactRead,
		Permission: "notif.unread_count",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleNotifUnreadCount,
	})
}

func handleMarkRead(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input markReadInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("notif.mark_read: %w", err)
	}
	if err := ac.Tx.MarkNotificationRead(ctx, sqlc.MarkNotificationReadParams{
		ReadAt: timestamp(),
		ID:     input.ID,
		UserID: input.UserID,
	}); err != nil {
		return nil, fmt.Errorf("notif.mark_read: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleMarkAllRead(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input markAllReadInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("notif.mark_all_read: %w", err)
	}
	if err := ac.Tx.MarkAllNotificationsRead(ctx, sqlc.MarkAllNotificationsReadParams{
		ReadAt: timestamp(),
		UserID: input.UserID,
	}); err != nil {
		return nil, fmt.Errorf("notif.mark_all_read: %w", err)
	}
	return map[string]bool{"ok": true}, nil
}

func handleNotifList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		UserID     string `json:"user_id"`
		Limit      int64  `json:"limit"`
		Offset     int64  `json:"offset"`
		UnreadOnly bool   `json:"unread_only"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("notif.list: %w", err)
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	if input.UnreadOnly {
		rows, err := ac.Tx.ListUnreadNotifications(ctx, sqlc.ListUnreadNotificationsParams{
			UserID: input.UserID,
			Limit:  input.Limit,
		})
		if err != nil {
			return nil, fmt.Errorf("notif.list: %w", err)
		}
		return rows, nil
	}
	rows, err := ac.Tx.ListNotifications(ctx, sqlc.ListNotificationsParams{
		UserID: input.UserID,
		Limit:  input.Limit,
		Offset: input.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("notif.list: %w", err)
	}
	return rows, nil
}

func handleNotifUnreadCount(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("notif.unread_count: %w", err)
	}
	count, err := ac.Tx.UnreadNotificationCount(ctx, input.UserID)
	if err != nil {
		return nil, fmt.Errorf("notif.unread_count: %w", err)
	}
	return map[string]int64{"count": count}, nil
}
