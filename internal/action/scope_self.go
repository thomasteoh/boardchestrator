package action

import (
	"fmt"
)

// checkScopeShape enforces the structural rules for the two tenant-less scope
// kinds before anything else runs (Q10). It lives in Dispatch itself rather
// than a ScopeResolver hook so it holds whatever hooks a dispatcher is built
// with:
//
//   - ScopePlatform and ScopeSelf actions never carry an org/team/project id.
//     A tenant id would otherwise let the permission check run against that
//     tenant's grants, where an org Owner holds "*".
//   - ScopeSelf actions are dispatched by a user acting for themselves. Agents,
//     API keys and service principals have no "self" rows to touch.
func checkScopeShape(def Definition, actor Actor, opts Opts) error {
	if def.Scope != ScopePlatform && def.Scope != ScopeSelf {
		return nil
	}
	if opts.Org != "" || opts.Team != "" || opts.Proj != "" {
		return fmt.Errorf("%w: %s is a %s-scope action and takes no org, team or project id", ErrForbidden, def.Name, def.Scope)
	}
	if def.Scope == ScopeSelf && actor.Type != ActorUser {
		return fmt.Errorf("%w: %s can only be run by a signed-in user", ErrForbidden, def.Name)
	}
	return nil
}

// SelfUserID returns the user id a ScopeSelf handler must act on: always the
// caller. claimed is an optional user_id from the input (older clients send
// one); a value naming anyone else is refused rather than silently ignored.
func SelfUserID(ac ActionCtx, claimed string) (string, error) {
	if claimed != "" && claimed != ac.Actor.ID {
		return "", fmt.Errorf("%w: can only act on your own account", ErrForbidden)
	}
	return ac.Actor.ID, nil
}
