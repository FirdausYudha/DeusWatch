package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAuth dikembalikan untuk kegagalan autentikasi (kredensial/token tidak valid).
// Sengaja generik agar tidak membocorkan apakah username ada (anti user-enumeration).
var ErrAuth = errors.New("auth: kredensial tidak valid")

// User adalah identitas terautentikasi.
type User struct {
	ID       string
	Username string
	Role     Role
	Disabled bool
}

// Store adalah repository auth (users, sessions, audit_log) di Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore membungkus pool yang sudah ada (berbagi dengan store utama).
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// dummyHash dipakai untuk menyamakan waktu saat username tidak ditemukan.
var dummyHash, _ = HashPassword("deuswatch-timing-equalizer")

// UserInfo adalah ringkasan user untuk API (tanpa hash password).
type UserInfo struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// ListUsers mengembalikan semua user (tanpa hash), terurut waktu buat.
func (s *Store) ListUsers(ctx context.Context) ([]UserInfo, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, disabled, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	defer rows.Close()
	out := make([]UserInfo, 0, 8)
	for rows.Next() {
		var u UserInfo
		var roleStr string
		if err := rows.Scan(&u.ID, &u.Username, &roleStr, &u.Disabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Role = Role(roleStr)
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserCount mengembalikan jumlah user.
func (s *Store) UserCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser membuat user dengan password yang di-hash Argon2id.
func (s *Store) CreateUser(ctx context.Context, username, password string, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("auth: role tidak valid: %q", role)
	}
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)`,
		username, h, string(role)); err != nil {
		return fmt.Errorf("auth: buat user: %w", err)
	}
	return nil
}

// EnsureAdmin membuat user admin bila tabel users masih kosong.
func (s *Store) EnsureAdmin(ctx context.Context, username, password string) (created bool, err error) {
	n, err := s.UserCount(ctx)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if err := s.CreateUser(ctx, username, password, RoleAdmin); err != nil {
		return false, err
	}
	return true, nil
}

// Login memverifikasi kredensial lalu membuat sesi; mengembalikan user + token mentah.
func (s *Store) Login(ctx context.Context, username, password string, ttl time.Duration) (*User, string, error) {
	var (
		u       User
		hash    string
		roleStr string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, disabled FROM users WHERE username=$1`, username).
		Scan(&u.ID, &u.Username, &hash, &roleStr, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = VerifyPassword(password, dummyHash) // samakan waktu
		return nil, "", ErrAuth
	}
	if err != nil {
		return nil, "", fmt.Errorf("auth: ambil user: %w", err)
	}
	if u.Disabled || VerifyPassword(password, hash) != nil {
		return nil, "", ErrAuth
	}
	u.Role = Role(roleStr)

	raw, th := newToken()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`,
		u.ID, th, time.Now().Add(ttl)); err != nil {
		return nil, "", fmt.Errorf("auth: buat sesi: %w", err)
	}
	return &u, raw, nil
}

// SessionUser memvalidasi token mentah dan mengembalikan user pemiliknya.
func (s *Store) SessionUser(ctx context.Context, rawToken string) (*User, error) {
	if rawToken == "" {
		return nil, ErrAuth
	}
	th := hashToken(rawToken)
	var (
		u       User
		roleStr string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.role, u.disabled
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`, th).
		Scan(&u.ID, &u.Username, &roleStr, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuth
	}
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrAuth
	}
	u.Role = Role(roleStr)
	_, _ = s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1`, th)
	return &u, nil
}

// Logout menghapus sesi untuk token tertentu.
func (s *Store) Logout(ctx context.Context, rawToken string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hashToken(rawToken))
	return err
}

// Audit menulis satu entri audit append-only (best-effort).
func (s *Store) Audit(ctx context.Context, actor, role, action, target, detail, sourceIP string) {
	var ip any
	if sourceIP != "" {
		ip = sourceIP
	}
	_, _ = s.pool.Exec(ctx,
		`INSERT INTO audit_log (actor, actor_role, action, target, detail, source_ip)
		 VALUES ($1,$2,$3,$4,$5,$6::inet)`,
		actor, role, action, nilIfEmpty(target), nilIfEmpty(detail), ip)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
