package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Passkey actions (WU-612, SPEC §7.9). Registration and sign-in are WebAuthn
// ceremonies run by internal/auth (authentication events, like linking an
// identity); these list, rename and delete the caller's own passkeys. All
// three are ScopeSelf: they only ever touch rows of ac.Actor.ID.

// MaxPasskeyNameLen bounds a passkey's name.
const MaxPasskeyNameLen = 64

// ErrPasskeyName refuses an empty or unprintable name.
var ErrPasskeyName = fmt.Errorf("%w: give the passkey a name of up to %d characters", ErrInvalidInput, MaxPasskeyNameLen)

// PasskeyView is one passkey as passkey.list returns it. It never carries
// the credential id or the public key.
type PasskeyView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Synced     bool   `json:"synced"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

type passkeyInput struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	UserID string `json:"user_id"`
}

func init() {
	Register(Definition{
		Name:       "passkey.list",
		Impact:     ImpactRead,
		Permission: "passkey.list",
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handlePasskeyList,
	})
	Register(Definition{
		Name:       "passkey.rename",
		Impact:     ImpactLow,
		Permission: "passkey.rename",
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handlePasskeyRename,
	})
	Register(Definition{
		Name:       "passkey.delete",
		Impact:     ImpactHigh,
		Permission: "passkey.delete",
		Scope:      ScopeSelf,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handlePasskeyDelete,
	})
	Register(Definition{
		Name:       "platform.settings.get",
		Impact:     ImpactRead,
		Permission: "platform.settings",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handlePlatformSettingsGet,
	})
	Register(Definition{
		Name:       "platform.settings.update",
		Impact:     ImpactHigh,
		Permission: "platform.settings",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handlePlatformSettingsUpdate,
	})
}

func decodePasskeyInput(in json.RawMessage) (passkeyInput, error) {
	var input passkeyInput
	if len(in) == 0 {
		return input, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(in)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		return input, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return input, nil
}

func handlePasskeyList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	input, err := decodePasskeyInput(in)
	if err != nil {
		return nil, err
	}
	uid, err := SelfUserID(ac, input.UserID)
	if err != nil {
		return nil, err
	}
	rows, err := ac.Tx.ListUserPasskeys(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("passkey.list: %w", err)
	}
	out := make([]PasskeyView, 0, len(rows))
	for _, r := range rows {
		out = append(out, PasskeyView{
			ID: r.ID, Name: r.Name, Synced: r.BackupState != 0,
			CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt.String,
		})
	}
	return map[string]any{"passkeys": out}, nil
}

// NormalisePasskeyName trims name and refuses it when empty, too long or
// carrying control characters.
func NormalisePasskeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > MaxPasskeyNameLen {
		return "", ErrPasskeyName
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", ErrPasskeyName
		}
	}
	return name, nil
}

func handlePasskeyRename(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	input, err := decodePasskeyInput(in)
	if err != nil {
		return nil, err
	}
	uid, err := SelfUserID(ac, input.UserID)
	if err != nil {
		return nil, err
	}
	if input.ID == "" {
		return nil, fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	name, err := NormalisePasskeyName(input.Name)
	if err != nil {
		return nil, err
	}
	n, err := ac.Tx.RenameUserPasskey(ctx, sqlc.RenameUserPasskeyParams{Name: name, ID: input.ID, UserID: uid})
	if err != nil {
		return nil, fmt.Errorf("passkey.rename: %w", err)
	}
	if n == 0 {
		// Another user's passkey (or none): indistinguishable to the caller.
		return nil, fmt.Errorf("passkey.rename: %w", sql.ErrNoRows)
	}
	return map[string]string{"id": input.ID, "name": name}, nil
}

func handlePasskeyDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	input, err := decodePasskeyInput(in)
	if err != nil {
		return nil, err
	}
	uid, err := SelfUserID(ac, input.UserID)
	if err != nil {
		return nil, err
	}
	if input.ID == "" {
		return nil, fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	pk, err := ac.Tx.FindUserPasskey(ctx, sqlc.FindUserPasskeyParams{ID: input.ID, UserID: uid})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("passkey.delete: %w", sql.ErrNoRows)
	}
	if err != nil {
		return nil, fmt.Errorf("passkey.delete: %w", err)
	}
	if _, err := ac.Tx.DeleteUserPasskey(ctx, sqlc.DeleteUserPasskeyParams{ID: pk.ID, UserID: uid}); err != nil {
		return nil, fmt.Errorf("passkey.delete: %w", err)
	}
	// Counted after the delete, inside the transaction, like identity.unlink.
	left, err := SignInMethodCount(ctx, ac.Tx.Queries, uid)
	if err != nil {
		return nil, fmt.Errorf("passkey.delete: %w", err)
	}
	if left < 1 {
		return nil, ErrLastSignInMethod
	}
	detail, err := json.Marshal(map[string]string{"passkey_id": pk.ID, "name": pk.Name})
	if err != nil {
		return nil, fmt.Errorf("passkey.delete: %w", err)
	}
	if err := ac.Tx.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID:         newID(),
		ActorType:  string(ac.Actor.Type),
		ActorID:    uid,
		Action:     "passkey.deleted",
		Subject:    pk.ID,
		DetailJson: string(detail),
		Ip:         ac.Actor.IP,
		CreatedAt:  time.Now().UTC().Format(timeFormat),
	}); err != nil {
		return nil, fmt.Errorf("passkey.delete: audit: %w", err)
	}
	return map[string]string{"id": pk.ID}, nil
}

// PlatformSettingsView is what platform.settings.get/update return.
type PlatformSettingsView struct {
	PasskeysEnabled bool `json:"passkeys_enabled"`
}

// PasskeysEnabledIn reads passkeys_enabled from platform_settings.settings_json:
// on unless explicitly false or 0 (SPEC §5).
func PasskeysEnabledIn(settingsJSON string) bool {
	var s struct {
		Passkeys any `json:"passkeys_enabled"`
	}
	if err := json.Unmarshal([]byte(settingsJSON), &s); err != nil {
		return true
	}
	switch v := s.Passkeys.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	}
	return true
}

// PasskeysEnabled reports the platform setting passkeys_enabled.
func PasskeysEnabled(ctx context.Context, q *sqlc.Queries) (bool, error) {
	ps, err := q.GetPlatformSettings(ctx)
	if err != nil {
		return false, fmt.Errorf("platform settings: %w", err)
	}
	return PasskeysEnabledIn(ps.SettingsJson), nil
}

func handlePlatformSettingsGet(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	on, err := PasskeysEnabled(ctx, ac.Tx.Queries)
	if err != nil {
		return nil, fmt.Errorf("platform.settings.get: %w", err)
	}
	return PlatformSettingsView{PasskeysEnabled: on}, nil
}

func handlePlatformSettingsUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		PasskeysEnabled *bool `json:"passkeys_enabled"`
	}
	dec := json.NewDecoder(strings.NewReader(string(in)))
	dec.DisallowUnknownFields()
	if len(in) > 0 {
		if err := dec.Decode(&input); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	if input.PasskeysEnabled == nil {
		return nil, fmt.Errorf("%w: nothing to change", ErrInvalidInput)
	}
	var v int64
	if *input.PasskeysEnabled {
		v = 1
	}
	if err := ac.Tx.SetPlatformPasskeysEnabled(ctx, v); err != nil {
		return nil, fmt.Errorf("platform.settings.update: %w", err)
	}
	return PlatformSettingsView{PasskeysEnabled: *input.PasskeysEnabled}, nil
}
