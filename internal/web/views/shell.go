// Package views contains templ components for the app shell and pages.
package views

import "encoding/json"

// hxHeaders builds the JSON value for the body's hx-headers attribute so every
// HTMX request carries the CSRF token (SPEC §3, §15). templ HTML-escapes the
// attribute value on render. An empty token yields "{}" — unauthenticated
// pages have no session to protect.
func hxHeaders(csrf string) string {
	if csrf == "" {
		return "{}"
	}
	b, err := json.Marshal(map[string]string{"X-CSRF-Token": csrf})
	if err != nil {
		// Marshaling a map[string]string of literals cannot fail.
		return "{}"
	}
	return string(b)
}

// Shell carries everything the base layout needs to render.
type Shell struct {
	// Title is the page title; the layout suffixes the product name.
	Title string
	// Nonce is the per-request CSP nonce applied to every script tag. Sourced
	// from the CSP middleware via the request context (WU-005).
	Nonce string
	// CSRF is the per-session CSRF token, injected into the body's hx-headers
	// so every HTMX mutating request carries it (SPEC §3, §15). Empty for
	// unauthenticated requests, which cannot mutate.
	CSRF string
	// Assets are cache-busted static URLs, resolved by the web package so
	// views stay free of asset-hashing logic.
	Assets ShellAssets
	// Active is the Href of the current primary-nav item ("" for none);
	// matching links render aria-current="page".
	Active string
}

// ShellAssets are the resolved (content-hashed) URLs of the shell's static
// dependencies.
type ShellAssets struct {
	AppCSS string
	HTMX   string
	Alpine string
	AppJS  string
}

// navItem is one primary-navigation destination.
type navItem struct {
	Label string
	Href  string
	// Mobile marks items that appear in the mobile bottom nav (kept to five
	// per WU-213: Boards, Backlog, Chat, Search, Notifications).
	Mobile bool
}

// navItems is the primary navigation. Most destinations land in later WUs;
// linking them now keeps the shell honest about its final shape.
var navItems = []navItem{
	{Label: "Boards", Href: "/boards", Mobile: true},
	{Label: "Backlog", Href: "/backlog", Mobile: true},
	{Label: "Chat", Href: "/chat", Mobile: true},
	{Label: "Search", Href: "/search", Mobile: true},
	{Label: "Notifications", Href: "/notifications", Mobile: true},
	{Label: "Settings", Href: "/settings"},
}
