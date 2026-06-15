package auth

import "fmt"

// Built-in roles (design doc section 4). A role is a convenient default bundle of
// permissions; an admin can override the effective set per user (granular RBAC).
type Role string

const (
	RoleViewer  Role = "viewer"  // read-only: dashboard & alerts
	RoleAnalyst Role = "analyst" // investigate, ack alerts, approve remediation, work tickets
	RoleAdmin   Role = "admin"   // full read-write-execute
)

// Granular permission. A user's effective permissions are either the role's
// defaults or an explicit per-user override set (the checklist in the UI).
type Permission string

const (
	PermViewDashboard      Permission = "view_dashboard"
	PermAckAlert           Permission = "ack_alert"
	PermApproveRemediation Permission = "approve_remediation"
	PermExecuteBlock       Permission = "execute_block"
	PermViewTickets        Permission = "view_tickets"
	PermManageTickets      Permission = "manage_tickets"
	PermManageRules        Permission = "manage_rules"
	PermManageAgents       Permission = "manage_agents"
	PermManageIntegrations Permission = "manage_integrations"
	PermManageUsers        Permission = "manage_users"
	PermManageSettings     Permission = "manage_settings"
)

// PermissionInfo describes a permission for the per-user RBAC checklist in the UI.
type PermissionInfo struct {
	Key   Permission `json:"key"`
	Label string     `json:"label"`
	Group string     `json:"group"`
}

// AllPermissions is the ordered catalog used to render the checklist and to validate input.
var AllPermissions = []PermissionInfo{
	{PermViewDashboard, "View dashboard & alerts", "Monitoring"},
	{PermAckAlert, "Acknowledge alerts", "Monitoring"},
	{PermViewTickets, "View tickets", "Ticketing"},
	{PermManageTickets, "Manage tickets (create / assign / close)", "Ticketing"},
	{PermApproveRemediation, "Approve / dismiss remediation", "Response"},
	{PermExecuteBlock, "Execute block actions", "Response"},
	{PermManageRules, "Manage detection rules", "Administration"},
	{PermManageAgents, "Manage agents", "Administration"},
	{PermManageIntegrations, "Manage integrations", "Administration"},
	{PermManageUsers, "Manage users & RBAC", "Administration"},
	{PermManageSettings, "Manage settings", "Administration"},
}

var validPermission = func() map[Permission]bool {
	m := make(map[Permission]bool, len(AllPermissions))
	for _, p := range AllPermissions {
		m[p.Key] = true
	}
	return m
}()

// rolePermissions maps each built-in role to its default permissions.
var rolePermissions = map[Role]map[Permission]bool{
	RoleViewer: {
		PermViewDashboard: true,
	},
	RoleAnalyst: {
		PermViewDashboard:      true,
		PermAckAlert:           true,
		PermApproveRemediation: true,
		PermViewTickets:        true,
		PermManageTickets:      true,
	},
	RoleAdmin: allPermissionsMap(),
}

func allPermissionsMap() map[Permission]bool {
	m := make(map[Permission]bool, len(AllPermissions))
	for _, p := range AllPermissions {
		m[p.Key] = true
	}
	return m
}

// Can reports whether the role has permission p by default.
func (r Role) Can(p Permission) bool {
	return rolePermissions[r][p]
}

// Valid reports whether r is a known built-in role.
func (r Role) Valid() bool {
	_, ok := rolePermissions[r]
	return ok
}

// Permissions returns the role's default permissions in catalog order.
func (r Role) Permissions() []Permission {
	out := make([]Permission, 0, len(AllPermissions))
	for _, p := range AllPermissions {
		if rolePermissions[r][p.Key] {
			out = append(out, p.Key)
		}
	}
	return out
}

// ParseRole validates a string into a Role.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("auth: unknown role: %q", s)
	}
	return r, nil
}

// ParsePermission validates a string into a known Permission.
func ParsePermission(s string) (Permission, error) {
	p := Permission(s)
	if !validPermission[p] {
		return "", fmt.Errorf("auth: unknown permission: %q", s)
	}
	return p, nil
}

// Can reports whether the user may perform p — using the explicit per-user
// permission set when present, otherwise falling back to the role's defaults.
func (u *User) Can(p Permission) bool {
	if u.Permissions != nil {
		for _, x := range u.Permissions {
			if x == p {
				return true
			}
		}
		return false
	}
	return u.Role.Can(p)
}

// EffectivePermissions returns the permissions actually in force for the user
// (the explicit override set, or the role's defaults when none is set).
func (u *User) EffectivePermissions() []Permission {
	if u.Permissions != nil {
		return u.Permissions
	}
	return u.Role.Permissions()
}
