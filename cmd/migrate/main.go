// Command migrate applies the DeusWatch SQL migrations to the database (in-house
// runner). Useful for CI / manual setup; the API also runs it automatically at start.
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
		log.Fatal("migrate: set DATABASE_URL or STORE_DSN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("migrate: connect: %v", err)
	}
	defer pool.Close()

	n, err := migrate.Apply(ctx, pool, migrations.FS)
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	if n == 0 {
		log.Println("migrate: no new migrations (database is up to date)")
	} else {
		log.Printf("migrate: %d migrations applied", n)
	}
}
