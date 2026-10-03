package server

import (
	"context"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestSessionSweepLoop (WU-613): the server's sweep purges expired sessions
// at start and on every tick, and leaves live ones.
func TestSessionSweepLoop(t *testing.T) {
	d := dbtest.New(t)
	if _, err := d.Exec(`INSERT INTO users (id, email) VALUES ('u1','u1@example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('h-old','u1','2000-01-01T00:00:00.000Z'),('h-live','u1','2999-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	s := NewWithDB(&config.Config{SecretKey: "0123456789abcdef0123456789abcdef", SessionSecret: "0123456789abcdef0123456789abcdef"}, d)
	if s.sessions == nil {
		t.Fatal("no session store")
	}
	count := func(h string) int {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, h).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.sessionSweepLoop(ctx, 20*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for count("h-old") != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count("h-old") != 0 {
		t.Fatal("expired session not purged")
	}
	// A session that expires later is purged on a later tick.
	if _, err := d.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('h-late','u1','2001-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	for count("h-late") != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if count("h-late") != 0 || count("h-live") != 1 {
		t.Fatalf("after ticks: late=%d live=%d", count("h-late"), count("h-live"))
	}
}
