//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type winEvent struct {
	RecordID       int64  `json:"RecordId"`
	ID             int    `json:"Id"`
	Message        string `json:"Message"`
	IPAddress      string `json:"IpAddress"`
	TargetUserName string `json:"TargetUserName"`
	LogonType      string `json:"LogonType"`
}

// wirePayload is the JSON the agent ships per Windows event (parsed by ingest.normalizeWindows).
type wirePayload struct {
	ID        int    `json:"id"`
	IP        string `json:"ip"`
	User      string `json:"user"`
	LogonType string `json:"logon_type"`
	Text      string `json:"text"`
}

// collectWinEventLog polls a Windows Event Log channel (Path) and sends new events.
// Uses PowerShell Get-WinEvent; tracks the highest RecordId to avoid resending.
// Compiled on Windows only.
func collectWinEventLog(ctx context.Context, s Source, out chan<- Line) error {
	channel := s.Path
	if channel == "" {
		channel = "System"
	}

	ticker := time.NewTicker(s.scanInterval(5 * time.Second))
	defer ticker.Stop()

	var lastID int64
	primed := false
	failing := false // so a persistent read error is logged once, not every tick
	for {
		events, err := queryWinEvents(ctx, channel, 50)
		if err != nil {
			// Surface the read error instead of swallowing it: the common cause is the
			// agent not running as SYSTEM/Administrator (the Security channel needs
			// elevation), which otherwise fails completely silently.
			if !failing {
				log.Printf("agent: wineventlog %q read error (is the agent running as SYSTEM/Admin? the Security log needs elevation): %v", channel, err)
				failing = true
			}
		} else {
			if failing {
				log.Printf("agent: wineventlog %q read recovered", channel)
				failing = false
			}
		}
		if err == nil && len(events) > 0 {
			maxID := lastID
			for _, e := range events {
				if e.RecordID > maxID {
					maxID = e.RecordID
				}
			}
			if !primed {
				lastID, primed = maxID, true // skip history; only send new ones
				log.Printf("agent: wineventlog %q ready (watching for new events after RecordId %d)", channel, maxID)
			} else {
				for i := len(events) - 1; i >= 0; i-- { // ascending (Get-WinEvent: newest first)
					if e := events[i]; e.RecordID > lastID {
						payload, _ := json.Marshal(wirePayload{
							ID: e.ID, IP: e.IPAddress, User: e.TargetUserName,
							LogonType: e.LogonType, Text: strings.TrimSpace(e.Message),
						})
						select {
						case out <- Line{Dataset: s.Dataset, Message: string(payload)}:
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
	// Pull the numeric EventID (Id) and the named EventData fields (IpAddress, TargetUserName,
	// LogonType) from each event's XML, so normalization keys off the language-independent ID.
	ps := fmt.Sprintf(
		"Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction Stop | ForEach-Object { "+
			"$d=@{}; try { $x=[xml]$_.ToXml(); foreach($n in $x.Event.EventData.Data){ if($n.Name){ $d[$n.Name]=[string]$n.'#text' } } } catch {}; "+
			"[pscustomobject]@{ RecordId=$_.RecordId; Id=$_.Id; Message=$_.Message; "+
			"IpAddress=$d['IpAddress']; TargetUserName=$d['TargetUserName']; LogonType=$d['LogonType'] } "+
			"} | ConvertTo-Json -Compress",
		channel, max)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	raw, err := cmd.Output()
	if err != nil {
		// Surface PowerShell's own message (e.g. "No events were found that match..."
		// is benign; "Attempted to perform an unauthorized operation" = not elevated).
		if ee, ok := err.(*exec.ExitError); ok {
			msg := strings.TrimSpace(string(ee.Stderr))
			// Benign: an empty/quiet channel makes Get-WinEvent "fail" with this — not
			// an error, just nothing new to ship.
			if strings.Contains(msg, "No events were found") {
				return nil, nil
			}
			if msg != "" {
				return nil, fmt.Errorf("%s", firstLine(msg))
			}
		}
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

// firstLine returns the first non-empty line (PowerShell errors span several lines;
// the first carries the useful message).
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			return ln
		}
	}
	return s
}
