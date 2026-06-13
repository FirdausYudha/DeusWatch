//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type winEvent struct {
	RecordID int64  `json:"RecordId"`
	Message  string `json:"Message"`
}

// collectWinEventLog mem-poll Windows Event Log channel (Path) dan mengirim event
// baru. Memakai PowerShell Get-WinEvent; melacak RecordId tertinggi agar tidak
// mengirim ulang. Hanya dikompilasi di Windows.
func collectWinEventLog(ctx context.Context, s Source, out chan<- Line) error {
	channel := s.Path
	if channel == "" {
		channel = "System"
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastID int64
	primed := false
	for {
		events, err := queryWinEvents(ctx, channel, 50)
		if err == nil && len(events) > 0 {
			maxID := lastID
			for _, e := range events {
				if e.RecordID > maxID {
					maxID = e.RecordID
				}
			}
			if !primed {
				lastID, primed = maxID, true // lewati histori; hanya kirim yang baru
			} else {
				for i := len(events) - 1; i >= 0; i-- { // ascending (Get-WinEvent: terbaru dulu)
					if e := events[i]; e.RecordID > lastID {
						select {
						case out <- Line{Dataset: s.Dataset, Message: strings.TrimSpace(e.Message)}:
						case <-ctx.Done():
							return nil
						}
					}
				}
				lastID = maxID
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func queryWinEvents(ctx context.Context, channel string, max int) ([]winEvent, error) {
	ps := fmt.Sprintf(
		"Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction Stop | "+
			"Select-Object RecordId,@{n='Message';e={$_.Message}} | ConvertTo-Json -Compress",
		channel, max)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []winEvent
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var one winEvent
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []winEvent{one}, nil
}
