package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(pw, h); err != nil {
		t.Fatalf("password benar seharusnya cocok: %v", err)
	}
	if err := VerifyPassword("salah", h); err == nil {
		t.Fatal("password salah seharusnya ditolak")
	}

	// Salt acak -> hash berbeda untuk password sama.
	h2, _ := HashPassword(pw)
	if h == h2 {
		t.Fatal("dua hash password sama seharusnya berbeda (salt acak)")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2i$v=19$m=1,t=1,p=1$x$y"} {
		if err := VerifyPassword("x", bad); err == nil {
			t.Fatalf("hash rusak %q seharusnya ditolak", bad)
		}
	}
}

func TestRBAC(t *testing.T) {
	// Viewer: hanya lihat.
	if !RoleViewer.Can(PermViewDashboard) {
		t.Fatal("viewer harus bisa lihat dashboard")
	}
	for _, p := range []Permission{PermManageRules, PermManageUsers, PermExecuteBlock, PermAckAlert} {
		if RoleViewer.Can(p) {
			t.Fatalf("viewer TIDAK boleh %s", p)
		}
	}

	// Analyst: investigasi/ack/approve, tapi tak kelola.
	if !RoleAnalyst.Can(PermAckAlert) || !RoleAnalyst.Can(PermApproveRemediation) {
		t.Fatal("analyst harus bisa ack & approve")
	}
	for _, p := range []Permission{PermManageRules, PermManageUsers, PermManageSettings, PermExecuteBlock} {
		if RoleAnalyst.Can(p) {
			t.Fatalf("analyst TIDAK boleh %s", p)
		}
	}

	// Admin: semua.
	for _, p := range []Permission{
		PermViewDashboard, PermAckAlert, PermApproveRemediation,
		PermManageRules, PermManageUsers, PermManageSettings, PermExecuteBlock,
	} {
		if !RoleAdmin.Can(p) {
			t.Fatalf("admin harus bisa %s", p)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, ok := range []string{"viewer", "analyst", "admin"} {
		if _, err := ParseRole(ok); err != nil {
			t.Fatalf("%q seharusnya valid: %v", ok, err)
		}
	}
	if _, err := ParseRole("superadmin"); err == nil {
		t.Fatal("role tak dikenal seharusnya ditolak")
	}
}
