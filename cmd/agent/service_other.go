//go:build !windows

package main

import "fmt"

// Di non-Windows, supervisi diserahkan ke systemd (lihat deploy/agent). Stub ini
// memastikan jalur service Windows tidak ikut ter-compile.

func runningAsService() bool { return false }

func runService() {}

func controlService(string) error {
	return fmt.Errorf("kontrol service hanya tersedia di Windows (gunakan systemd di Linux)")
}
