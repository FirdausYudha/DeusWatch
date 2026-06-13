package auth

import (
	"encoding/json"
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
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "body tidak valid", http.StatusBadRequest)
			return
		}
		u, token, err := s.Login(r.Context(), req.Username, req.Password, SessionTTL)
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

// MeHandler mengembalikan identitas user terautentikasi saat ini.
func MeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"username": u.Username, "role": u.Role})
	}
}
