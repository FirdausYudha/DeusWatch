package auth

import "fmt"

// Built-in roles (design doc section 4).
type Role string

const (
	RoleViewer  Role = "viewer"  // read-only: dashboard & alerts
	RoleAnalyst Role = "analyst" // investigate, ack alerts, approve remediation — cannot manage
	RoleAdmin   Role = "admin"   // full read-write-execute
)

// Granular permission. Pro mode (custom role builder) will assemble roles from these.
type Permission string

const (
	PermViewDashboard      Permission = "view_dashboard"
	PermAckAlert           Permission = "ack_alert"
	PermApproveRemediation Permission = "approve_remediation"
	PermManageRules        Permission = "manage_rules"
	PermManageUsers        Permission = "manage_users"
	PermManageAgents       Permission = "manage_agents"
	PermManageSettings     Permission = "manage_settings"
	PermExecuteBlock       Permission = "execute_block"
)

// rolePermissions maps each built-in role to its permissions.
var rolePermissions = map[Role]map[Permission]bool{
	RoleViewer: {
		PermViewDashboard: true,
	},
	RoleAnalyst: {
		PermViewDashboard:      true,
		PermAckAlert:           true,
		PermApproveRemediation: true,
	},
	RoleAdmin: {
		PermViewDashboard:      true,
		PermAckAlert:           true,
		PermApproveRemediation: true,
		PermManageRules:        true,
		PermManageUsers:        true,
		PermManageAgents:       true,
		PermManageSettings:     true,
		PermExecuteBlock:       true,
	},
}

// Can reports whether the role has permission p.
func (r Role) Can(p Permission) bool {
	return rolePermissions[r][p]
}

// Valid reports whether r is a known built-in role.
func (r Role) Valid() bool {
	_, ok := rolePermissions[r]
	return ok
}

// ParseRole validates a string into a Role.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("auth: unknown role: %q", s)
	}
	return r, nil
}
