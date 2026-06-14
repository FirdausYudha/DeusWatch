package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(pw, h); err != nil {
		t.Fatalf("correct password should match: %v", err)
	}
	if err := VerifyPassword("wrong", h); err == nil {
		t.Fatal("wrong password should be rejected")
	}

	// Random salt -> different hash for the same password.
	h2, _ := HashPassword(pw)
	if h == h2 {
		t.Fatal("two hashes of the same password should differ (random salt)")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2i$v=19$m=1,t=1,p=1$x$y"} {
		if err := VerifyPassword("x", bad); err == nil {
			t.Fatalf("malformed hash %q should be rejected", bad)
		}
	}
}

func TestRBAC(t *testing.T) {
	// Viewer: read-only.
	if !RoleViewer.Can(PermViewDashboard) {
		t.Fatal("viewer must be able to view the dashboard")
	}
	for _, p := range []Permission{PermManageRules, PermManageUsers, PermExecuteBlock, PermAckAlert} {
		if RoleViewer.Can(p) {
			t.Fatalf("viewer must NOT have %s", p)
		}
	}

	// Analyst: investigate/ack/approve, but cannot manage.
	if !RoleAnalyst.Can(PermAckAlert) || !RoleAnalyst.Can(PermApproveRemediation) {
		t.Fatal("analyst must be able to ack & approve")
	}
	for _, p := range []Permission{PermManageRules, PermManageUsers, PermManageSettings, PermExecuteBlock} {
		if RoleAnalyst.Can(p) {
			t.Fatalf("analyst must NOT have %s", p)
		}
	}

	// Admin: everything.
	for _, p := range []Permission{
		PermViewDashboard, PermAckAlert, PermApproveRemediation,
		PermManageRules, PermManageUsers, PermManageSettings, PermExecuteBlock,
	} {
		if !RoleAdmin.Can(p) {
			t.Fatalf("admin must be able to %s", p)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, ok := range []string{"viewer", "analyst", "admin"} {
		if _, err := ParseRole(ok); err != nil {
			t.Fatalf("%q should be valid: %v", ok, err)
		}
	}
	if _, err := ParseRole("superadmin"); err == nil {
		t.Fatal("unknown role should be rejected")
	}
}
