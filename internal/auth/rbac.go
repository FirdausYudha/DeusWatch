package auth

import "fmt"

// Role bawaan (design doc bagian 4).
type Role string

const (
	RoleViewer  Role = "viewer"  // read-only: dashboard & alert
	RoleAnalyst Role = "analyst" // investigasi, ack alert, approve remediasi — tak bisa kelola
	RoleAdmin   Role = "admin"   // full read-write-execute
)

// Permission granular. Mode pro (custom role builder) akan merakit role dari ini.
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

// rolePermissions memetakan role bawaan ke izinnya.
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

// Can melaporkan apakah role memiliki permission p.
func (r Role) Can(p Permission) bool {
	return rolePermissions[r][p]
}

// Valid melaporkan apakah r adalah role bawaan yang dikenal.
func (r Role) Valid() bool {
	_, ok := rolePermissions[r]
	return ok
}

// ParseRole memvalidasi string menjadi Role.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("auth: role tidak dikenal: %q", s)
	}
	return r, nil
}
