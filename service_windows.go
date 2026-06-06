//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "twsnmpv3proxy"

type proxyService struct {
	configPath string
	localIP    string
}

func (m *proxyService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// 1. Setup cancelable context for proxy lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Load configuration
	config, err := LoadConfig(m.configPath)
	if err != nil {
		log.Printf("[Service] Failed to load config %s: %v", m.configPath, err)
		return false, 1
	}

	// 3. Initialize Agent Client
	agentClient, err := NewAgentClient(config, m.localIP)
	if err != nil {
		log.Printf("[Service] Failed to initialize Agent Client: %v", err)
		return false, 2
	}
	defer agentClient.Close()

	// 4. Initialize Proxy Server
	proxyServer, err := NewProxyServer(config, agentClient, m.localIP)
	if err != nil {
		log.Printf("[Service] Failed to initialize Proxy Server: %v", err)
		return false, 3
	}

	// 5. Start proxy server
	errChan := make(chan error, 1)
	go func() {
		errChan <- proxyServer.Start(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Printf("[Service] %s service running", serviceName)

loop:
	for {
		select {
		case err := <-errChan:
			if err != nil {
				log.Printf("[Service] Proxy server failed: %v", err)
				return false, 4
			}
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Printf("[Service] Service stop/shutdown signal received")
				cancel()
				changes <- svc.Status{State: svc.StopPending}
				break loop
			default:
				log.Printf("[Service] Unexpected service control request: #%d", c.Cmd)
			}
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

// runService registers and runs the app under the Windows service manager.
func runService(configPath string, localIP string) {
	err := svc.Run(serviceName, &proxyService{configPath: configPath, localIP: localIP})
	if err != nil {
		log.Fatalf("Windows Service execution failed: %v", err)
	}
}

// handleServiceCommand performs install, uninstall, start, and stop functions.
func handleServiceCommand(cmd, configPath, localIP string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to SCM: %w", err)
	}
	defer m.Disconnect()

	switch cmd {
	case "install":
		s, err := m.OpenService(serviceName)
		if err == nil {
			s.Close()
			return fmt.Errorf("service %s already exists", serviceName)
		}

		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}

		absConfigPath := ResolvePath(configPath)
		var serviceArgs []string
		if absConfigPath != "" {
			serviceArgs = append(serviceArgs, "-config", absConfigPath)
		}
		if localIP != "" {
			serviceArgs = append(serviceArgs, "-local-ip", localIP)
		}

		s, err = m.CreateService(serviceName, execPath, mgr.Config{
			DisplayName: "TWSNMP SNMPv3 Proxy",
			Description: "Bridges secure SNMPv3 manager requests to a local SNMPv2c agent",
			StartType:   mgr.StartAutomatic,
		}, serviceArgs...)
		if err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}
		defer s.Close()

		// Attempt to install event log source (non-fatal if it fails)
		_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
		fmt.Printf("Service %s installed successfully.\n", serviceName)
		return nil

	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service %s is not installed", serviceName)
		}
		defer s.Close()

		// Stop if running
		_, _ = s.Control(svc.Stop)

		err = s.Delete()
		if err != nil {
			return fmt.Errorf("failed to delete service: %w", err)
		}

		_ = eventlog.Remove(serviceName)
		fmt.Printf("Service %s uninstalled successfully.\n", serviceName)
		return nil

	case "start":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service %s is not installed", serviceName)
		}
		defer s.Close()

		err = s.Start()
		if err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
		fmt.Printf("Service %s started.\n", serviceName)
		return nil

	case "stop":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service %s is not installed", serviceName)
		}
		defer s.Close()

		status, err := s.Control(svc.Stop)
		if err != nil {
			return fmt.Errorf("failed to stop service: %w", err)
		}

		// Poll status until stopped
		timeout := time.Now().Add(10 * time.Second)
		for status.State != svc.Stopped {
			if time.Now().After(timeout) {
				return fmt.Errorf("timeout waiting for service to stop")
			}
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				return fmt.Errorf("failed to query service status: %w", err)
			}
		}
		fmt.Printf("Service %s stopped.\n", serviceName)
		return nil

	default:
		return fmt.Errorf("unknown service command: %s", cmd)
	}
}

// isWindowsService returns true if the application is running under SCM.
func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}
