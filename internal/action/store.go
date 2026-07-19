package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// timeFormat matches the SQLite storage format used across the schema
// (SPEC §3: UTC ISO-8601, millisecond precision, Z suffix). Mirrors
// internal/auth so stored timestamps are comparable app-wide.
const timeFormat = "2006-01-02T15:04:05.000Z"

// Queries is the transaction-scoped data handle handed to handlers via
// ActionCtx.Tx. It wraps sqlc's generated Queries bound to the dispatch
// transaction so handlers write through the same tx Dispatch opened. As real
// action packages land they will type-assert or use exported helpers here;
// exposing the sqlc handle keeps handlers free of their own tx management.
type Queries struct {
	*sqlc.Queries
}

// dbIdempotencyStore is the default IdempotencyStore, backed by the
// idempotency_keys table.
type dbIdempotencyStore struct {
	db *sql.DB
}

func (s dbIdempotencyStore) Get(ctx context.Context, key string) (json.RawMessage, bool, error) {
	row, err := sqlc.New(s.db).GetIdempotencyKey(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("action: get idempotency key: %w", err)
	}
	return json.RawMessage(row.ResultJson), true, nil
}

func (s dbIdempotencyStore) Put(ctx context.Context, key, actorRef, action string, result json.RawMessage, at time.Time) error {
	if len(result) == 0 {
		result = json.RawMessage("null")
	}
	err := sqlc.New(s.db).CreateIdempotencyKey(ctx, sqlc.CreateIdempotencyKeyParams{
		Key:        key,
		Actor:      actorRef,
		Action:     action,
		ResultJson: string(result),
		CreatedAt:  at.UTC().Format(timeFormat),
	})
	if err != nil {
		return fmt.Errorf("action: store idempotency key: %w", err)
	}
	return nil
}

// dbAuditSink is the default AuditSink, backed by the audit_log table.
type dbAuditSink struct {
	db  *sql.DB
	now Clock
}

func (s dbAuditSink) Append(ctx context.Context, e AuditEntry) error {
	detail := e.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	org := sql.NullString{}
	if e.Org != "" {
		org = sql.NullString{String: e.Org, Valid: true}
	}
	err := sqlc.New(s.db).CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID:         newID(),
		OrgID:      org,
		ActorType:  string(e.ActorType),
		ActorID:    e.ActorID,
		Action:     e.Action,
		Subject:    e.Subject,
		DetailJson: string(detail),
		Ip:         e.IP,
		CreatedAt:  s.now().UTC().Format(timeFormat),
	})
	if err != nil {
		return fmt.Errorf("action: append audit row: %w", err)
	}
	return nil
}
