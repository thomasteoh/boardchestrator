package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Org settings -> Single sign-on -> Provisioning: JIT provisioning and IdP
// group -> role mappings (WU-608, SPEC §7.5). Changes dispatch org.sso.update
// and org.idp_mapping.* as the session user.

func init() {
	for k, v := range map[string]string{
		"provisioning_saved": "Provisioning settings saved.",
		"mapping_created":    "Group mapping added.",
		"mapping_deleted":    "Group mapping deleted.",
	} {
		ssoNotices[k] = v
	}
	for k, v := range map[string]string{
		"jit_owner":         "The default role for new people can't be an owner role.",
		"jit_no_role":       "Choose a default role before turning on just-in-time provisioning.",
		"group_claim":       "The group claim must be a claim name or dotted path, with no spaces.",
		"mapping_role":      "That role isn't available in this organisation.",
		"mapping_resource":  "That team or project isn't in this organisation.",
		"mapping_provider":  "That identity provider isn't on this organisation.",
		"mapping_group":     "Enter the group value exactly as your identity provider sends it (up to 256 characters).",
		"mapping_exists":    "That group is already mapped for that organisation, team or project.",
		"mapping_limit":     "This organisation has reached its limit of 500 group mappings.",
		"mapping_not_found": "That group mapping isn't on this organisation.",
		"platform_org":      "The platform organisation can't use provisioning.",
	} {
		ssoErrors[k] = v
	}
}

// provisioningErrorCode maps a refusal to a fixed ssoErrors code ("" =
// unexpected).
func provisioningErrorCode(err error) string {
	for _, c := range []struct {
		code string
		err  error
	}{
		{"jit_owner", action.ErrJITOwnerRole}, {"jit_no_role", action.ErrJITNoRole},
		{"group_claim", action.ErrGroupClaim}, {"mapping_role", action.ErrMappingRole},
		{"mapping_resource", action.ErrMappingResource}, {"mapping_provider", action.ErrMappingProvider},
		{"mapping_group", action.ErrMappingGroup}, {"mapping_exists", action.ErrMappingExists},
		{"mapping_limit", action.ErrMappingLimit}, {"mapping_not_found", action.ErrMappingNotFound},
		{"platform_org", action.ErrPlatformOrgSSO},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return ""
}

// provisioningSection builds the Provisioning section. st and provs come
// from org.sso.get and org.idp.list, already dispatched (so the caller holds
// org.sso); the role, team and project names are org-scoped reads.
func provisioningSection(r *http.Request, actor action.Actor, orgID, csrf string, st action.OrgSSOView, provs []idp.ProviderView) (views.OrgProvisioningData, error) {
	d := views.OrgProvisioningData{
		OrgID: url.PathEscape(orgID), CSRF: csrf, JITEnabled: st.JITEnabled, JITRoleID: st.JITDefaultRoleID,
		GroupSync: st.GroupSync, GroupClaim: st.GroupClaim,
	}
	out, err := orgDispatch(r, actor, orgID, action.ActionIdPMappingList, struct{}{})
	if err != nil {
		return d, err
	}
	mappings, _ := out.([]action.IdPMappingView)

	ctx := r.Context()
	q := sqlc.New(disp.DB())
	roles, err := q.ListRolesByOrg2(ctx, orgID)
	if err != nil {
		return d, err
	}
	roleName := map[string]string{}
	for _, ro := range roles {
		if ro.OrgID != orgID && ro.IsSystem != 1 {
			continue // a platform-only role
		}
		roleName[ro.ID] = ro.Name
		d.Roles = append(d.Roles, views.SelectOption{Value: ro.ID, Label: ro.Name})
		if !action.OwnerEquivalent(ro) {
			d.JITRoles = append(d.JITRoles, views.SelectOption{Value: ro.ID, Label: ro.Name})
		}
	}
	target := map[string]string{"org:" + orgID: "Organisation"}
	d.Targets = append(d.Targets, views.SelectOption{Value: "org:" + orgID, Label: "Organisation"})
	teams, err := q.ListOrgTeams(ctx, orgID)
	if err != nil {
		return d, err
	}
	for _, t := range teams {
		label := "Team: " + t.Name
		target["team:"+t.ID] = label
		d.Targets = append(d.Targets, views.SelectOption{Value: "team:" + t.ID, Label: label})
	}
	projects, err := q.ListOrgProjects(ctx, orgID)
	if err != nil {
		return d, err
	}
	for _, p := range projects {
		label := "Project: " + p.Name
		target["project:"+p.ID] = label
		d.Targets = append(d.Targets, views.SelectOption{Value: "project:" + p.ID, Label: label})
	}
	provName := map[string]string{}
	for _, p := range provs {
		provName[p.ID] = p.DisplayName
		d.Providers = append(d.Providers, views.SelectOption{Value: p.ID, Label: p.DisplayName})
	}
	for _, m := range mappings {
		scope := target[m.ResourceType+":"+m.ResourceID]
		if scope == "" {
			scope = "Removed " + m.ResourceType
		}
		role := roleName[m.RoleID]
		if role == "" {
			role = m.RoleID
		}
		prov := ""
		if m.ProviderID != "" {
			prov = provName[m.ProviderID]
			if prov == "" {
				prov = m.ProviderID
			}
		}
		d.Mappings = append(d.Mappings, views.OrgMappingRow{ID: m.ID, Group: m.GroupValue, Provider: prov, Scope: scope, Role: role})
	}
	return d, nil
}

// provisioningOutcome lands back on the SSO page.
func provisioningOutcome(w http.ResponseWriter, r *http.Request, orgID string, err error, notice string) {
	if err != nil && !errors.Is(err, action.ErrForbidden) && !errors.Is(err, action.ErrScope) {
		if code := provisioningErrorCode(err); code != "" {
			orgSSORedirect(w, r, orgID, "error", code)
			return
		}
	}
	orgSSOOutcome(w, r, orgID, err, notice)
}

// handleOrgProvisioning saves the JIT and group-sync settings.
func handleOrgProvisioning(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	jit := r.PostFormValue("jit_enabled") == "1"
	sync := r.PostFormValue("group_sync") == "1"
	role := r.PostFormValue("jit_default_role_id")
	claim := r.PostFormValue("group_claim")
	_, err := orgDispatch(r, actor, orgID, "org.sso.update", map[string]any{
		"jit_enabled": jit, "jit_default_role_id": role, "group_sync": sync, "group_claim": claim,
	})
	provisioningOutcome(w, r, orgID, err, "provisioning_saved")
}

// handleOrgMappingCreate adds a group mapping; target is "<type>:<id>".
func handleOrgMappingCreate(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	rt, rid, _ := strings.Cut(r.PostFormValue("target"), ":")
	_, err := orgDispatch(r, actor, orgID, action.ActionIdPMappingCreate, map[string]string{
		"group_value": r.PostFormValue("group_value"), "role_id": r.PostFormValue("role_id"),
		"provider_id": r.PostFormValue("provider_id"), "resource_type": rt, "resource_id": rid,
	})
	provisioningOutcome(w, r, orgID, err, "mapping_created")
}

// handleOrgMappingDelete deletes a group mapping.
func handleOrgMappingDelete(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	_, err := orgDispatch(r, actor, orgID, action.ActionIdPMappingDelete, map[string]string{"id": chi.URLParam(r, "id")})
	provisioningOutcome(w, r, orgID, err, "mapping_deleted")
}
