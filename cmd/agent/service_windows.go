//go:build windows

package main

// Integrasi Windows Service NATIVE (menggantikan Scheduled Task). Agent berjalan di
// bawah Service Control Manager (SCM): lapor status, tangani Stop/Shutdown, dan
// minta restart saat config push berubah lewat recovery action.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "DeusWatchAgent"

// runningAsService melaporkan apakah proses dijalankan oleh SCM (bukan konsol).
func runningAsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// agentService memenuhi svc.Handler.
type agentService struct{}

// Execute adalah loop utama service: menjalankan runAgent dan merespons perintah SCM.
// Bila runAgent berhenti karena config push baru, kami keluar dengan kode != 0 agar
// recovery action SCM me-restart service (sehingga config baru diterapkan).
func (m *agentService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	configChanged := false
	done := make(chan struct{})
	go func() {
		runAgent(ctx, func() { configChanged = true; cancel() })
		close(done)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
loop:
	for {
		select {
		case <-done:
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				break loop
			default:
			}
		}
	}

	status <- svc.Status{State: svc.StopPending}
	cancel()
	<-done
	if configChanged {
		return false, 1 // exit error -> SCM recovery me-restart untuk menerapkan config
	}
	return false, 0
}

// runService menjalankan agent di bawah SCM.
func runService() {
	if err := svc.Run(serviceName, &agentService{}); err != nil {
		os.Exit(1)
	}
}

// controlService menangani sub-perintah -service install|uninstall|start|stop.
func controlService(cmd string) error {
	switch cmd {
	case "install":
		return installService()
	case "uninstall", "remove":
		return removeService()
	case "start":
		return startService()
	case "stop":
		return stopService()
	default:
		return fmt.Errorf("perintah tak dikenal %q (install|uninstall|start|stop)", cmd)
	}
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		_ = s.Close()
		return fmt.Errorf("service %q sudah terpasang", serviceName)
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "DeusWatch Agent",
		Description:  "Kolektor log endpoint DeusWatch (mTLS).",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	// Recovery: restart pada kegagalan (termasuk exit code config-change) — interval 5s,
	// reset hitungan kegagalan tiap 1 jam.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, uint32((time.Hour).Seconds())); err != nil {
		return fmt.Errorf("set recovery: %w", err)
	}
	fmt.Printf("Service %q terpasang (otomatis saat boot, SYSTEM).\n", serviceName)
	fmt.Println("Set GATEWAY_URL & CERT_DIR sebagai environment variable mesin, lalu: deuswatch-agent.exe -service start")
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q tak ditemukan: %w", serviceName, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("Service %q dihapus.\n", serviceName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q tak ditemukan: %w", serviceName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Printf("Service %q dijalankan.\n", serviceName)
	return nil
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q tak ditemukan: %w", serviceName, err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	fmt.Printf("Sinyal stop dikirim ke service %q.\n", serviceName)
	return nil
}
