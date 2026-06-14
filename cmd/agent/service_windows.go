//go:build windows

package main

// NATIVE Windows Service integration (replacing Scheduled Task). The agent runs under
// the Service Control Manager (SCM): it reports status, handles Stop/Shutdown, and
// requests a restart when the pushed config changes via a recovery action.

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

// runningAsService reports whether the process was launched by the SCM (not the console).
func runningAsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// agentService satisfies svc.Handler.
type agentService struct{}

// Execute is the service main loop: it runs runAgent and responds to SCM commands.
// If runAgent stops due to a new pushed config, we exit with a non-zero code so the
// SCM recovery action restarts the service (applying the new config).
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
		return false, 1 // exit error -> SCM recovery restarts to apply the config
	}
	return false, 0
}

// runService runs the agent under the SCM.
func runService() {
	if err := svc.Run(serviceName, &agentService{}); err != nil {
		os.Exit(1)
	}
}

// controlService handles the -service install|uninstall|start|stop sub-commands.
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
		return fmt.Errorf("unknown command %q (install|uninstall|start|stop)", cmd)
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
		return fmt.Errorf("service %q is already installed", serviceName)
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "DeusWatch Agent",
		Description:  "DeusWatch endpoint log collector (mTLS).",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	// Recovery: restart on failure (including the config-change exit code) — 5s interval,
	// reset the failure count every 1 hour.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, uint32((time.Hour).Seconds())); err != nil {
		return fmt.Errorf("set recovery: %w", err)
	}
	fmt.Printf("Service %q installed (automatic at boot, SYSTEM).\n", serviceName)
	fmt.Println("Set GATEWAY_URL & CERT_DIR as machine environment variables, then: deuswatch-agent.exe -service start")
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
		return fmt.Errorf("service %q not found: %w", serviceName, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("Service %q removed.\n", serviceName)
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
		return fmt.Errorf("service %q not found: %w", serviceName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Printf("Service %q started.\n", serviceName)
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
		return fmt.Errorf("service %q not found: %w", serviceName, err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	fmt.Printf("Stop signal sent to service %q.\n", serviceName)
	return nil
}
