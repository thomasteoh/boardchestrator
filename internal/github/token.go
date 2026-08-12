package github

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// TokenForUser returns the decrypted GitHub token for a user, if connected.
// Phase-5 wiki edits use this to commit as the user; the token is never
// exposed — callers use it to sign GitHub API requests. secretKey must be the
// 32-byte AES key used at connect time (tenant.PadKey of the app secret).
func TokenForUser(ctx context.Context, db *sql.DB, secretKey []byte, userID string) (string, bool, error) {
	conn, err := sqlc.New(db).FindGithubConnection(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil // not connected
		}
		return "", false, fmt.Errorf("github: find connection: %w", err)
	}
	if conn.TokenEnc == "" {
		return "", false, nil
	}
	plain, err := tenant.Decrypt(secretKey, conn.TokenEnc)
	if err != nil {
		return "", false, fmt.Errorf("github: decrypt token: %w", err)
	}
	return plain, true, nil
}
