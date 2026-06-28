// Package agentinstall serves the public one-line agent installer: the install
// scripts (Linux/Windows) and the cross-compiled agent binaries. These are not
// secret (the enrollment token is the credential), so the endpoints are unauthenticated
// — the same model as Wazuh's public packages.
package agentinstall

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

//go:embed install.sh install.ps1
var scripts embed.FS

// Handler serves the installer scripts and binaries. binDir holds the
// cross-compiled binaries named deuswatch-agent-<os>-<arch>[.exe].
type Handler struct{ binDir string }

func New(binDir string) *Handler { return &Handler{binDir: binDir} }

func (h *Handler) script(w http.ResponseWriter, name, contentType string) {
	b, err := scripts.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(b)
}

// InstallSh serves the Linux installer (GET /api/agent/install.sh).
func (h *Handler) InstallSh(w http.ResponseWriter, _ *http.Request) {
	h.script(w, "install.sh", "text/x-shellscript; charset=utf-8")
}

// InstallPs1 serves the Windows installer (GET /api/agent/install.ps1).
func (h *Handler) InstallPs1(w http.ResponseWriter, _ *http.Request) {
	h.script(w, "install.ps1", "text/plain; charset=utf-8")
}

var allowedOS = map[string]bool{"linux": true, "windows": true}

// Binary serves a cross-compiled agent binary (GET /api/agent/binary/{os}/{arch}).
func (h *Handler) Binary(w http.ResponseWriter, r *http.Request) {
	goos := filepath.Base(r.PathValue("os"))
	arch := filepath.Base(r.PathValue("arch"))
	if !allowedOS[goos] {
		http.Error(w, "unknown os", http.StatusBadRequest)
		return
	}
	name := fmt.Sprintf("deuswatch-agent-%s-%s", goos, arch)
	if goos == "windows" {
		name += ".exe"
	}
	f, err := os.Open(filepath.Join(h.binDir, name))
	if err != nil {
		http.Error(w, fmt.Sprintf("agent binary for %s/%s not built — run scripts/build-agent", goos, arch), http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	http.ServeContent(w, r, name, time.Time{}, f)
}
