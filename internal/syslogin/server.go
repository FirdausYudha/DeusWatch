package syslogin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"deuswatch/internal/bus"
	"deuswatch/internal/ingest"
)

// Publisher publishes a payload to a subject (satisfied by *bus.Bus).
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// maxLine caps one syslog message (generous; typical lines are < 2 KB).
const maxLine = 64 << 10

// Server listens for syslog on UDP and TCP and feeds each message into the pipeline.
type Server struct {
	addr           string
	pub            Publisher
	defaultDataset string // used when a message has no usable TAG (e.g. "syslog")
}

// New builds a Server. addr is a host:port (e.g. ":5514"); defaultDataset labels messages that
// carry no program tag.
func New(addr string, pub Publisher, defaultDataset string) *Server {
	if defaultDataset == "" {
		defaultDataset = "syslog"
	}
	return &Server{addr: addr, pub: pub, defaultDataset: defaultDataset}
}

// Run starts the UDP and TCP listeners and blocks until ctx is cancelled. A failure to bind
// either transport is returned so the caller can log it and continue without syslog.
func (s *Server) Run(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("syslog: resolve %s: %w", s.addr, err)
	}
	uconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("syslog: listen udp %s: %w", s.addr, err)
	}
	tln, err := net.Listen("tcp", s.addr)
	if err != nil {
		uconn.Close()
		return fmt.Errorf("syslog: listen tcp %s: %w", s.addr, err)
	}
	log.Printf("syslog: listening on %s (udp+tcp)", s.addr)

	go func() { <-ctx.Done(); uconn.Close(); tln.Close() }()
	go s.serveUDP(ctx, uconn)
	go s.serveTCP(ctx, tln)
	<-ctx.Done()
	return nil
}

// serveUDP reads datagrams; each may carry one or several newline-separated messages.
func (s *Server) serveUDP(ctx context.Context, c *net.UDPConn) {
	buf := make([]byte, maxLine)
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return // closed on shutdown
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			s.handle(ctx, line)
		}
	}
}

// serveTCP accepts connections and reads messages framed either newline-delimited or by an
// octet count (RFC 6587: "<len> <msg>"), which rsyslog uses by default over TCP.
func (s *Server) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReaderSize(conn, maxLine)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		// Octet-counting framing starts with an ASCII length + space.
		if b, err := r.Peek(1); err == nil && b[0] >= '0' && b[0] <= '9' {
			if s.readOctetFramed(ctx, r) {
				continue
			}
		}
		line, err := r.ReadString('\n')
		if line != "" {
			s.handle(ctx, line)
		}
		if err != nil {
			return
		}
	}
}

// readOctetFramed reads one "<len> <msg>" frame. Returns false if it isn't actually octet-framed
// (so the caller falls back to line reading).
func (s *Server) readOctetFramed(ctx context.Context, r *bufio.Reader) bool {
	lenStr, err := r.ReadString(' ')
	if err != nil {
		return false
	}
	n := 0
	for _, c := range strings.TrimSpace(lenStr) {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 || n > maxLine {
		return false
	}
	msg := make([]byte, n)
	if _, err := readFull(r, msg); err != nil {
		return false
	}
	s.handle(ctx, string(msg))
	return true
}

func readFull(r *bufio.Reader, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// handle parses one line, normalizes it, and publishes the event.
func (s *Server) handle(ctx context.Context, line string) {
	m, ok := Parse(line, time.Now())
	if !ok {
		return
	}
	dataset := strings.ToLower(strings.TrimSpace(m.Tag))
	if dataset == "" {
		dataset = s.defaultDataset
	}
	tag := "syslog"
	if m.Host != "" {
		tag = "syslog/" + m.Host // shown in the dashboard's Agent column
	}
	ev, _ := ingest.Normalize(ingest.RawLog{
		Timestamp: m.Timestamp, Host: m.Host, AgentID: tag, Dataset: dataset, Message: m.Content,
	})
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if err := s.pub.Publish(ctx, bus.SubjectLogsNormalized, data); err != nil {
		log.Printf("syslog: publish: %v", err)
	}
}
