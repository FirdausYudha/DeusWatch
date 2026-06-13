// Package agent adalah kolektor log endpoint DeusWatch: men-tail berkas log dan
// mengirim baris mentah ke gateway lewat mTLS.
package agent

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"time"
)

// FollowFile membaca baris dari path dan mengirimkannya ke out. Bila fromStart
// true mulai dari awal berkas; selain itu dari akhir. Setelah mencapai EOF ia
// terus mengikuti (poll) baris baru hingga ctx dibatalkan.
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
			case <-time.After(300 * time.Millisecond): // tunggu data baru
			}
		case err != nil:
			return err
		}
	}
}
