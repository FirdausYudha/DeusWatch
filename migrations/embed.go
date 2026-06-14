// Package migrations embeds the SQL migration files into the binary so they can be
// applied automatically at start (see internal/migrate). Making this folder a single
// Go package also keeps the embed path valid (go:embed may not use "..").
package migrations

import "embed"

// FS holds all migration files (*.up.sql / *.down.sql).
//
//go:embed *.sql
var FS embed.FS
