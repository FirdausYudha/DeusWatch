package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// SessionTTL adalah masa berlaku sesi (token rotasi/refresh menyusul).
const SessionTTL = 24 * time.Hour

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// LoginHandler memverifikasi username/password dan mengembalikan token sesi.
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
			http.Error(w, "body tidak valid", http.StatusBadRequest)
			return
		}
		u, token, err := s.Login(r.Context(), req.Username, req.Password, req.TOTP, SessionTTL)
		if errors.Is(err, Err2FARequired) {
			// Password benar; minta kode 2FA (UI menampilkan field kode).
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "2fa_required"})
			return
		}
		if err != nil {
			s.Audit(r.Context(), req.Username, "", "login_failed", "", "", ClientIP(r))
			http.Error(w, "kredensial tidak valid", http.StatusUnauthorized)
			return
		}
		s.Audit(r.Context(), u.Username, string(u.Role), "login", "", "", ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{
			"token": token, "username": u.Username, "role": u.Role,
		})
	}
}

// LogoutHandler menghapus sesi pemanggil.
func (s *Store) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tok := bearerToken(r); tok != "" {
			_ = s.Logout(r.Context(), tok)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UsersHandler: GET = daftar user, POST = buat user. WAJIB dibungkus
// Middleware + RequirePermission(PermManageUsers) — hanya admin.
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
				Username string `json:"username"`
				Password string `json:"password"`
				Role     string `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "body tidak valid", http.StatusBadRequest)
				return
			}
			role, err := ParseRole(req.Role)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(req.Username) < 3 || len(req.Password) < 8 {
				http.Error(w, "username minimal 3 & password minimal 8 karakter", http.StatusBadRequest)
				return
			}
			if err := s.CreateUser(r.Context(), req.Username, req.Password, role); err != nil {
				http.Error(w, "gagal membuat user (username sudah dipakai?)", http.StatusBadRequest)
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

// Setup2FAHandler menghasilkan secret TOTP baru (BELUM diaktifkan sampai
// dikonfirmasi via Enable2FAHandler). Self-service untuk akun sendiri.
func (s *Store) Setup2FAHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secret, otpauthURL, err := GenerateTOTPSecret(u.Username)
		if err != nil {
			http.Error(w, "gagal membuat secret", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": otpauthURL})
	}
}

// Enable2FAHandler mengaktifkan 2FA setelah memverifikasi kode terhadap secret.
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
			http.Error(w, "body tidak valid", http.StatusBadRequest)
			return
		}
		if req.Secret == "" || !ValidateTOTP(req.Secret, req.Code) {
			http.Error(w, "kode 2FA tidak valid", http.StatusBadRequest)
			return
		}
		if err := s.SetTOTPSecret(r.Context(), u.ID, req.Secret); err != nil {
			http.Error(w, "gagal menyimpan", http.StatusInternalServerError)
			return
		}
		s.Audit(r.Context(), u.Username, string(u.Role), "enable_2fa", u.Username, "", ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
	}
}

// Disable2FAHandler menonaktifkan 2FA setelah memverifikasi kode saat ini.
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
			http.Error(w, "body tidak valid", http.StatusBadRequest)
			return
		}
		secret, err := s.totpSecretOf(r.Context(), u.ID)
		if err != nil || secret == "" {
			http.Error(w, "2FA tidak aktif", http.StatusBadRequest)
			return
		}
		if !ValidateTOTP(secret, req.Code) {
			http.Error(w, "kode 2FA tidak valid", http.StatusBadRequest)
			return
		}
		if err := s.ClearTOTPSecret(r.Context(), u.ID); err != nil {
			http.Error(w, "gagal menyimpan", http.StatusInternalServerError)
			return
		}
		s.Audit(r.Context(), u.Username, string(u.Role), "disable_2fa", u.Username, "", ClientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
	}
}

// MeHandler mengembalikan identitas user terautentikasi saat ini + status 2FA.
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
		})
	}
}
