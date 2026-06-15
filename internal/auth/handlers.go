package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// SessionTTL is the session lifetime (token rotation/refresh to follow).
const SessionTTL = 24 * time.Hour

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// LoginHandler verifies username/password and returns a session token.
func (s *Store) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		u, token, err := s.Login(r.Context(), req.Username, req.Password, req.TOTP, SessionTTL)
		if errors.Is(err, Err2FARequired) {
			// Password correct; ask for the 2FA code (the UI shows a code field).
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "2fa_required"})
			return
		}
		if err != nil {
			s.Audit(r.Context(), req.Username, "", "login_failed", "", "", ClientIP(r))
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		s.Audit(r.Context(), u.Username, string(u.Role), "login", "", "", ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{
			"token": token, "username": u.Username, "role": u.Role,
			"permissions": u.EffectivePermissions(),
		})
	}
}

// RegisterHandler (PUBLIC): self-registration creates a viewer-role account then
// auto-logs in (returning a token). Whether the endpoint is enabled is controlled in
// cmd/api via REGISTRATION_ENABLED. Error messages are deliberately generic (anti user-enumeration).
func (s *Store) RegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if len(req.Username) < 3 || len(req.Password) < 8 {
			http.Error(w, "username must be at least 3 and password at least 8 characters", http.StatusBadRequest)
			return
		}
		if err := s.CreateUser(r.Context(), req.Username, req.Password, RoleViewer, nil); err != nil {
			http.Error(w, "registration failed (username may already be taken)", http.StatusBadRequest)
			return
		}
		s.Audit(r.Context(), req.Username, string(RoleViewer), "register", req.Username, "", ClientIP(r))

		// Auto-login so the user is signed in right after registering.
		u, token, err := s.Login(r.Context(), req.Username, req.Password, "", SessionTTL)
		if err != nil {
			writeJSON(w, http.StatusCreated, map[string]any{"username": req.Username, "role": RoleViewer})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"token": token, "username": u.Username, "role": u.Role,
			"permissions": u.EffectivePermissions(),
		})
	}
}

// LogoutHandler deletes the caller's session.
func (s *Store) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tok := bearerToken(r); tok != "" {
			_ = s.Logout(r.Context(), tok)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UsersHandler: GET = list users, POST = create user. MUST be wrapped with
// Middleware + RequirePermission(PermManageUsers) — admin only.
func (s *Store) UsersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			users, err := s.ListUsers(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, users)

		case http.MethodPost:
			var req struct {
				Username    string    `json:"username"`
				Password    string    `json:"password"`
				Role        string    `json:"role"`
				Permissions *[]string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			role, err := ParseRole(req.Role)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			perms, err := parsePermissions(req.Permissions)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(req.Username) < 3 || len(req.Password) < 8 {
				http.Error(w, "username must be at least 3 and password at least 8 characters", http.StatusBadRequest)
				return
			}
			if err := s.CreateUser(r.Context(), req.Username, req.Password, role, perms); err != nil {
				http.Error(w, "failed to create user (username already taken?)", http.StatusBadRequest)
				return
			}
			actor, _ := UserFrom(r.Context())
			s.Audit(r.Context(), actorName(actor), actorRole(actor), "create_user", req.Username, "role="+req.Role, ClientIP(r))
			writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username, "role": req.Role})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// parsePermissions validates a list of permission keys. A nil pointer (key absent in
// the request) returns nil = "inherit the role's defaults"; a non-nil list (even empty)
// returns an explicit custom set.
func parsePermissions(raw *[]string) ([]Permission, error) {
	if raw == nil {
		return nil, nil
	}
	out := make([]Permission, 0, len(*raw))
	for _, s := range *raw {
		p, err := ParsePermission(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// UpdateUserHandler (admin): updates a user's role and permission override set.
// MUST be wrapped with Middleware + RequirePermission(PermManageUsers).
func (s *Store) UpdateUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		var req struct {
			Role        string    `json:"role"`
			Permissions *[]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		role, err := ParseRole(req.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		perms, err := parsePermissions(req.Permissions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.UpdateUser(r.Context(), id, role, perms); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor, _ := UserFrom(r.Context())
		s.Audit(r.Context(), actorName(actor), actorRole(actor), "update_user", id, "role="+req.Role, ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "id": id})
	}
}

// PermissionsHandler returns the permission catalog + each role's default permission
// set — everything the UI needs to render and prefill the RBAC checklist.
func (s *Store) PermissionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"catalog": AllPermissions,
			"role_defaults": map[Role][]Permission{
				RoleViewer:  RoleViewer.Permissions(),
				RoleAnalyst: RoleAnalyst.Permissions(),
				RoleAdmin:   RoleAdmin.Permissions(),
			},
		})
	}
}

func actorName(u *User) string {
	if u != nil {
		return u.Username
	}
	return "unknown"
}

func actorRole(u *User) string {
	if u != nil {
		return string(u.Role)
	}
	return ""
}

// Setup2FAHandler generates a new TOTP secret (NOT enabled until confirmed via
// Enable2FAHandler). Self-service for the caller's own account.
func (s *Store) Setup2FAHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secret, otpauthURL, err := GenerateTOTPSecret(u.Username)
		if err != nil {
			http.Error(w, "failed to generate secret", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": otpauthURL})
	}
}

// Enable2FAHandler enables 2FA after verifying the code against the secret.
func (s *Store) Enable2FAHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Secret string `json:"secret"`
			Code   string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if req.Secret == "" || !ValidateTOTP(req.Secret, req.Code) {
			http.Error(w, "invalid 2FA code", http.StatusBadRequest)
			return
		}
		if err := s.SetTOTPSecret(r.Context(), u.ID, req.Secret); err != nil {
			http.Error(w, "failed to save", http.StatusInternalServerError)
			return
		}
		s.Audit(r.Context(), u.Username, string(u.Role), "enable_2fa", u.Username, "", ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
	}
}

// Disable2FAHandler disables 2FA after verifying the current code.
func (s *Store) Disable2FAHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		secret, err := s.totpSecretOf(r.Context(), u.ID)
		if err != nil || secret == "" {
			http.Error(w, "2FA not enabled", http.StatusBadRequest)
			return
		}
		if !ValidateTOTP(secret, req.Code) {
			http.Error(w, "invalid 2FA code", http.StatusBadRequest)
			return
		}
		if err := s.ClearTOTPSecret(r.Context(), u.ID); err != nil {
			http.Error(w, "failed to save", http.StatusInternalServerError)
			return
		}
		s.Audit(r.Context(), u.Username, string(u.Role), "disable_2fa", u.Username, "", ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
	}
}

// MeHandler returns the currently authenticated user's identity + 2FA status.
func (s *Store) MeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		enabled, _ := s.HasTOTP(r.Context(), u.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"username": u.Username, "role": u.Role, "twofa_enabled": enabled,
			"permissions": u.EffectivePermissions(),
		})
	}
}
