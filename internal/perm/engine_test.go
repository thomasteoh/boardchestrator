package perm

import (
	"testing"
)

func TestCheckPermissionExactMatch(t *testing.T) {
	if !checkPermission("task.create", []string{"task.create"}) {
		t.Fatal("exact match should pass")
	}
}

func TestCheckPermissionWildcardSuffix(t *testing.T) {
	if !checkPermission("task.create", []string{"task.*"}) {
		t.Fatal("wildcard suffix should match")
	}
	if !checkPermission("task.delete", []string{"task.*"}) {
		t.Fatal("wildcard suffix should match any verb")
	}
	if checkPermission("tasking.something", []string{"task.*"}) {
		t.Fatal("wildcard should not cross domain boundary")
	}
}

func TestCheckPermissionFullWildcard(t *testing.T) {
	if !checkPermission("org.delete", []string{"*"}) {
		t.Fatal("full wildcard should match anything")
	}
	if !checkPermission("anything.else", []string{"*"}) {
		t.Fatal("full wildcard should match anything")
	}
}

func TestCheckPermissionMultipleGrants(t *testing.T) {
	if !checkPermission("comment.read", []string{"org.read", "comment.*"}) {
		t.Fatal("should match via comment.*")
	}
}

func TestCheckPermissionNoMatch(t *testing.T) {
	if checkPermission("org.delete", []string{"org.read", "team.*"}) {
		t.Fatal("org.delete not in grants — should deny")
	}
}

func TestCheckPermissionEmpty(t *testing.T) {
	if checkPermission("anything", []string{}) {
		t.Fatal("empty grants should deny")
	}
}
