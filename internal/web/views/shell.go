// Package views contains templ components for the app shell and pages.
package views

// Shell carries everything the base layout needs to render.
type Shell struct {
	// Title is the page title; the layout suffixes the product name.
	Title string
	// Nonce is the per-request CSP nonce applied to every script tag.
	// WU-005's CSP middleware becomes the source; until then callers pass a
	// per-request placeholder.
	Nonce string
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
