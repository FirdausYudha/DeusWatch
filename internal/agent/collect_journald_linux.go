//go:build linux

package agent

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
)

// collectJournald men-tail systemd journal lewat `journalctl -f`. Path (bila ada)
// dipakai sebagai filter unit (-u). Hanya dikompilasi di Linux.
func collectJournald(ctx context.Context, s Source, out chan<- Line) error {
	args := []string{"-f", "-o", "cat", "--no-pager"}
	if s.Path != "" {
		args = append(args, "-u", s.Path)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl start: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		select {
		case out <- Line{Dataset: s.Dataset, Message: sc.Text()}:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return nil
		}
	}
	return cmd.Wait()
}
