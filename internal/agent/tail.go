// Package agent is the DeusWatch endpoint log collector: it tails log files and
// sends raw lines to the gateway over mTLS.
package agent

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"time"
)

// FollowFile reads lines from path and sends them to out. If fromStart is true it
// starts from the beginning of the file; otherwise from the end. After reaching EOF
// it keeps following (polling) for new lines until ctx is cancelled.
func FollowFile(ctx context.Context, path string, fromStart bool, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if !fromStart {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if trimmed := strings.TrimRight(line, "\r\n"); trimmed != "" {
				select {
				case out <- trimmed:
				case <-ctx.Done():
					return nil
				}
			}
		}
		switch {
		case err == io.EOF:
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(300 * time.Millisecond): // wait for new data
			}
		case err != nil:
			return err
		}
	}
}
