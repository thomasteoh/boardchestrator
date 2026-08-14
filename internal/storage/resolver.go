package storage

import (
	"context"
	"sync"
)

// ConfigLoader returns the decrypted S3Config for an org ("" when the org has
// no S3 backend configured — fall back to local). Implemented by the caller
// (server) which owns DB access and the tenant secret key.
type ConfigLoader func(ctx context.Context, orgID string) (S3Config, error)

// Resolver selects the attachment Store for an org: an S3Store when the org has
// an S3 backend configured (via org_secrets), otherwise the local store.
// S3 clients are cached per org (SPEC §9: per-org backend, local fallback).
type Resolver struct {
	local   Store
	load    ConfigLoader
	maxSize int64
	allowed []string

	mu   sync.Mutex
	orgs map[string]*S3Store
}

// NewResolver builds a per-org store resolver. local is the fallback store;
// load fetches an org's S3 config (returning an error or a zero config for
// local fallback); maxSize and contentTypes configure S3 stores.
func NewResolver(local Store, load ConfigLoader, maxSize int64, contentTypes []string) *Resolver {
	return &Resolver{
		local:   local,
		load:    load,
		maxSize: maxSize,
		allowed: contentTypes,
		orgs:    map[string]*S3Store{},
	}
}

// Resolve returns the Store for orgID, caching per-org S3 clients.
func (r *Resolver) Resolve(ctx context.Context, orgID string) (Store, error) {
	cfg, err := r.load(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if cfg.Bucket == "" { // no S3 configured → local
		return r.local, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.orgs[orgID]; ok {
		return s, nil
	}
	client, err := NewS3Client(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewS3Store(client, cfg, r.maxSize, r.allowed)
	if err != nil {
		return nil, err
	}
	r.orgs[orgID] = s
	return s, nil
}

// Local returns the fallback local store.
func (r *Resolver) Local() Store { return r.local }
