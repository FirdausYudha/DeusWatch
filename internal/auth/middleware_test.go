package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequirePermission(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	guarded := RequirePermission(PermManageUsers, ok)

	cases := []struct {
		name string
		user *User
		want int
	}{
		{"admin allowed", &User{Username: "a", Role: RoleAdmin}, http.StatusOK},
		{"analyst denied", &User{Username: "b", Role: RoleAnalyst}, http.StatusForbidden},
		{"viewer denied", &User{Username: "c", Role: RoleViewer}, http.StatusForbidden},
		{"no user denied", nil, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
			if c.user != nil {
				req = req.WithContext(withUser(context.Background(), c.user))
			}
			rr := httptest.NewRecorder()
			guarded.ServeHTTP(rr, req)
			if rr.Code != c.want {
				t.Fatalf("status=%d, want %d", rr.Code, c.want)
			}
		})
	}
}
