package idp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// Display positions for env-seeded providers.
const (
	positionGoogle = 10
	positionGitHub = 20
	positionOIDC   = 100
)

// SeedFromConfig upserts the env-configured providers as managed_by='env'
// rows (SPEC §7.1): BC_GOOGLE_* → "google", BC_GITHUB_* → "github",
// BC_OIDC_<NAME>_* → "<name>". Env rows whose variables are gone are disabled,
// never deleted, because identities and sessions keep referring to the id.
// A UI-managed row with the same id is left alone.
//
// Seeding is startup configuration, like migrations, so it writes directly
// rather than through action dispatch. Problems with individual providers are
// joined into the returned error; the rest are still seeded.
func SeedFromConfig(ctx context.Context, d *sql.DB, encKey []byte, cfg *config.Config) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("idp: seed: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := sqlc.New(tx)

	var errs []error
	seeded := map[string]bool{}
	upsert := func(p sqlc.UpsertEnvAuthProviderParams, secret string) {
		existing, err := q.GetAuthProvider(ctx, p.ID)
		switch {
		case err == nil && existing.ManagedBy != "env":
			errs = append(errs, fmt.Errorf("idp: env provider %q ignored: a provider with that id is managed in the UI", p.ID))
			return
		case err == nil && existing.ClientSecretEnc != "":
			// Keep the stored ciphertext when the secret is unchanged, so a
			// restart is not a write.
			if old, derr := tenant.Decrypt(encKey, existing.ClientSecretEnc); derr == nil && old == secret {
				p.ClientSecretEnc = existing.ClientSecretEnc
			}
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			errs = append(errs, fmt.Errorf("idp: env provider %q: %w", p.ID, err))
			return
		}
		if secret != "" && p.ClientSecretEnc == "" {
			enc, err := tenant.Encrypt(encKey, secret)
			if err != nil {
				errs = append(errs, fmt.Errorf("idp: env provider %q: seal secret: %w", p.ID, err))
				return
			}
			p.ClientSecretEnc = enc
		}
		if err := q.UpsertEnvAuthProvider(ctx, p); err != nil {
			errs = append(errs, fmt.Errorf("idp: env provider %q: %w", p.ID, err))
			return
		}
		seeded[p.ID] = true
	}

	if cfg.GoogleClientID != "" {
		issuer := cfg.GoogleIssuer
		if issuer == "" {
			issuer = GoogleIssuer
		}
		g, _ := LookupPreset("google")
		upsert(sqlc.UpsertEnvAuthProviderParams{
			ID: "google", Kind: KindOIDC, Preset: "google", DisplayName: g.DisplayName,
			Issuer: issuer, ClientID: cfg.GoogleClientID, Scopes: strings.Join(g.Scopes, " "),
			ClaimMapJson: "{}", TrustEmail: 1, AllowSignup: 1, Position: positionGoogle,
		}, cfg.GoogleClientSecret)
	}
	if cfg.GitHubClientID != "" {
		web := cfg.GitHubWebBase
		if web == "" {
			web = GitHubWebBase
		}
		gh, _ := LookupPreset("github")
		upsert(sqlc.UpsertEnvAuthProviderParams{
			ID: "github", Kind: KindGitHub, Preset: "github", DisplayName: gh.DisplayName,
			Issuer: web, ClientID: cfg.GitHubClientID, Scopes: strings.Join(gh.Scopes, " "),
			ClaimMapJson: "{}", TrustEmail: 1, AllowSignup: 1, Position: positionGitHub,
		}, cfg.GitHubClientSecret)
	}
	for _, p := range cfg.OIDCProviders {
		params, err := envOIDCParams(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		upsert(params, p.ClientSecret)
	}

	all, err := q.ListAuthProviders(ctx)
	if err != nil {
		return fmt.Errorf("idp: seed: list: %w", err)
	}
	for _, row := range all {
		if row.ManagedBy == "env" && row.Enabled == 1 && !seeded[row.ID] {
			if err := q.DisableEnvAuthProvider(ctx, row.ID); err != nil {
				return fmt.Errorf("idp: seed: disable %s: %w", row.ID, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("idp: seed: commit: %w", err)
	}
	return errors.Join(errs...)
}

// envOIDCParams validates one BC_OIDC_<NAME>_* provider and fills preset
// defaults. Sign-up defaults to allowed for env providers: the operator who
// set the variables controls the instance (WU-604 revisits sign-up policy).
func envOIDCParams(p config.OIDCEnvProvider) (sqlc.UpsertEnvAuthProviderParams, error) {
	fail := func(err error) (sqlc.UpsertEnvAuthProviderParams, error) {
		return sqlc.UpsertEnvAuthProviderParams{}, fmt.Errorf("idp: BC_OIDC_%s_*: %w",
			strings.ToUpper(strings.ReplaceAll(p.ID, "-", "_")), err)
	}
	if err := ValidateID(p.ID); err != nil {
		return fail(err)
	}
	preset, ok := LookupPreset(p.Preset)
	if !ok || preset.Kind != KindOIDC {
		return fail(fmt.Errorf("unknown preset %q", p.Preset))
	}
	issuer := strings.TrimSpace(p.Issuer)
	if issuer == "" {
		// Presets without required parameters (google, gitlab.com) need no
		// issuer variable.
		iss, err := preset.ExpandIssuer(nil)
		if err != nil {
			return fail(errors.New("_ISSUER is required for this preset"))
		}
		issuer = iss
	} else if err := ValidateIssuer(issuer); err != nil {
		return fail(err)
	}
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = preset.Scopes
	}
	claimMap := "{}"
	if p.GroupsClaim != "" {
		b, err := json.Marshal(map[string]string{"groups": p.GroupsClaim})
		if err != nil {
			return fail(err)
		}
		claimMap = string(b)
	}
	trust := preset.TrustEmail
	if p.TrustEmail != nil {
		trust = *p.TrustEmail
	}
	signup := true
	if p.AllowSignup != nil {
		signup = *p.AllowSignup
	}
	name := p.DisplayName
	if name == "" {
		name = preset.DisplayName
	}
	return sqlc.UpsertEnvAuthProviderParams{
		ID: p.ID, Kind: KindOIDC, Preset: preset.ID, DisplayName: name, Issuer: issuer,
		ClientID: p.ClientID, Scopes: strings.Join(scopes, " "), ClaimMapJson: claimMap,
		TrustEmail: b2i(trust), AllowSignup: b2i(signup), Position: positionOIDC,
	}, nil
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
