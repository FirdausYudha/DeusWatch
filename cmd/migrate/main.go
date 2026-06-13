// Command migrate menerapkan migrasi SQL DeusWatch ke database (runner in-house).
// Berguna untuk CI / setup manual; API juga menjalankannya otomatis saat start.
//
//	DATABASE_URL=postgres://... go run ./cmd/migrate
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/migrate"
	"deuswatch/migrations"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("STORE_DSN")
	}
	if dsn == "" {
		log.Fatal("migrate: set DATABASE_URL atau STORE_DSN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("migrate: koneksi: %v", err)
	}
	defer pool.Close()

	n, err := migrate.Apply(ctx, pool, migrations.FS)
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	if n == 0 {
		log.Println("migrate: tak ada migrasi baru (database mutakhir)")
	} else {
		log.Printf("migrate: %d migrasi diterapkan", n)
	}
}
