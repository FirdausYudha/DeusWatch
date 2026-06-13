// Package migrations menyematkan berkas SQL migrasi ke dalam biner sehingga dapat
// diterapkan otomatis saat start (lihat internal/migrate). Menjadikan folder ini
// satu paket Go juga membuat path embed valid (go:embed tak boleh memakai "..").
package migrations

import "embed"

// FS berisi semua berkas migrasi (*.up.sql / *.down.sql).
//
//go:embed *.sql
var FS embed.FS
