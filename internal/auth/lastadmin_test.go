package auth

import (
	"strings"
	"testing"
)

// canManageUsers has to agree with the middleware exactly, or the guard protects a different
// question than the one that decides access. An explicit override REPLACES the role's defaults, so
// the role alone is not the answer in either direction.
func TestCanManageUsersMatchesTheMiddleware(t *testing.T) {
	for _, c := range []struct {
		name  string
		role  Role
		perms []Permission
		want  bool
	}{
		{"admin with role defaults", RoleAdmin, nil, true},
		{"analyst with role defaults", RoleAnalyst, nil, false},
		{"viewer with role defaults", RoleViewer, nil, false},
		// The case that makes a role check wrong: an admin whose override omits the permission
		// cannot administer anything, however the UI labels them.
		{"admin whose override drops manage_users", RoleAdmin, []Permission{PermViewDashboard}, false},
		// And the mirror: a viewer who was granted it explicitly can.
		{"viewer granted manage_users", RoleViewer, []Permission{PermManageUsers}, true},
		// An empty (not nil) override is a real override that grants nothing.
		{"empty override", RoleAdmin, []Permission{}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := canManageUsers(c.role, c.perms)
			if got != c.want {
				t.Errorf("canManageUsers = %v, want %v", got, c.want)
			}
			// Same inputs, through the path the middleware actually uses.
			u := User{Role: c.role, Permissions: c.perms}
			if u.Can(PermManageUsers) != got {
				t.Errorf("disagrees with User.Can, which is the one that gates requests")
			}
		})
	}
}

// countAdmins is remainingAdmins without a database, so the decision logic can be exercised
// directly. The store method is a thin wrapper over ListUsers plus this.
func countAdmins(users []UserInfo, targetID string, after *UserInfo) int {
	n := 0
	for _, u := range users {
		if u.ID == targetID {
			if after == nil {
				continue
			}
			u = *after
		}
		if u.Disabled {
			continue
		}
		if canManageUsers(u.Role, u.Permissions) {
			n++
		}
	}
	return n
}

func TestRemainingAdmins(t *testing.T) {
	seeded := UserInfo{ID: "1", Username: "admin", Role: RoleAdmin}
	mine := UserInfo{ID: "2", Username: "firdaus", Role: RoleAdmin}
	analyst := UserInfo{ID: "3", Username: "soc", Role: RoleAnalyst}

	// The thing the operator actually wants: drop the seeded `admin` once they have their own.
	all := []UserInfo{seeded, mine, analyst}
	if n := countAdmins(all, "1", nil); n != 1 {
		t.Errorf("deleting the seeded admin should leave 1 administrator, got %d", n)
	}

	// The lockout: the same delete when they are the only two, and the other is not an admin.
	if n := countAdmins([]UserInfo{seeded, analyst}, "1", nil); n != 0 {
		t.Errorf("deleting the only administrator must leave 0, got %d", n)
	}

	// Demotion reaches the same dead end more quietly.
	demoted := UserInfo{ID: "2", Username: "firdaus", Role: RoleViewer}
	if n := countAdmins([]UserInfo{mine, analyst}, "2", &demoted); n != 0 {
		t.Errorf("demoting the only administrator must leave 0, got %d", n)
	}
	// But demoting one of two is fine.
	if n := countAdmins(all, "2", &demoted); n != 1 {
		t.Errorf("demoting one of two administrators should leave 1, got %d", n)
	}

	// A disabled administrator is not one anybody can reach, so it must not hold the door open
	// for a delete that would otherwise be refused.
	disabled := UserInfo{ID: "4", Username: "old-admin", Role: RoleAdmin, Disabled: true}
	if n := countAdmins([]UserInfo{mine, disabled}, "2", nil); n != 0 {
		t.Errorf("a disabled administrator must not count, got %d", n)
	}

	// Stripping the permission while keeping the admin role is still a lockout.
	stripped := UserInfo{ID: "2", Role: RoleAdmin, Permissions: []Permission{PermViewDashboard}}
	if n := countAdmins([]UserInfo{mine, analyst}, "2", &stripped); n != 0 {
		t.Errorf("an admin whose override drops manage_users is not an administrator, got %d", n)
	}
}

// The refusal is shown to the operator, so it has to say how to get where they were going rather
// than only that they cannot.
func TestErrLastAdminIsActionable(t *testing.T) {
	msg := ErrLastAdmin{action: "delete this user"}.Error()
	for _, want := range []string{"delete this user", "Create another administrator"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal should contain %q:\n%s", want, msg)
		}
	}
}
