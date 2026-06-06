package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// AgentClient wraps the SNMPv2c client connection with thread-safety and connection recovery.
type AgentClient struct {
	mu     sync.Mutex
	client *gosnmp.GoSNMP
}

// NewAgentClient creates a new AgentClient instance.
func NewAgentClient(config *Config, localIP string) (*AgentClient, error) {
	addr := strings.TrimSpace(config.AgentAddress)
	if addr == "" {
		return nil, fmt.Errorf("agent address cannot be empty")
	}

	host, portStr, err := net.SplitHostPort(addr)
	var port uint16 = 161
	if err != nil {
		// If splitting fails, assume it's just a host/IP and use default port 161
		host = addr
	} else {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err == nil {
			port = uint16(p)
		}
	}

	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      port,
		Community: config.AgentCommunity,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(3) * time.Second,
		Retries:   1,
	}

	if localIP != "" {
		client.LocalAddr = localIP + ":0"
		log.Printf("[AgentClient] Bound local IP for outgoing requests to: %s", client.LocalAddr)
	}

	agent := &AgentClient{
		client: client,
	}

	// Connect initially
	if err := agent.connect(); err != nil {
		log.Printf("[AgentClient] Initial connect warning: %v (will retry on first request)", err)
	}

	return agent, nil
}

// connect performs the connection logic. Must be called with lock held if concurrent,
// or during initialization.
func (a *AgentClient) connect() error {
	if a.client.Conn != nil {
		a.client.Conn.Close()
		a.client.Conn = nil
	}
	log.Printf("[AgentClient] Connecting to SNMPv2c agent at %s:%d...", a.client.Target, a.client.Port)
	return a.client.Connect()
}

// Close closes the underlying agent connection.
func (a *AgentClient) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client.Conn != nil {
		a.client.Conn.Close()
		a.client.Conn = nil
	}
}

// Get executes an SNMP GET query with retry and socket recovery.
func (a *AgentClient) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return a.requestWithRetry(func() (*gosnmp.SnmpPacket, error) {
		return a.client.Get(oids)
	})
}

// GetNext executes an SNMP GETNEXT query with retry and socket recovery.
func (a *AgentClient) GetNext(oids []string) (*gosnmp.SnmpPacket, error) {
	return a.requestWithRetry(func() (*gosnmp.SnmpPacket, error) {
		return a.client.GetNext(oids)
	})
}

// GetBulk executes an SNMP GETBULK query with retry and socket recovery.
func (a *AgentClient) GetBulk(oids []string, nonRepeaters uint8, maxRepetitions uint32) (*gosnmp.SnmpPacket, error) {
	return a.requestWithRetry(func() (*gosnmp.SnmpPacket, error) {
		return a.client.GetBulk(oids, nonRepeaters, maxRepetitions)
	})
}

// requestWithRetry executes the SNMP operation with up to 5 attempts and exponential backoff.
func (a *AgentClient) requestWithRetry(op func() (*gosnmp.SnmpPacket, error)) (*gosnmp.SnmpPacket, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var result *gosnmp.SnmpPacket
	var err error

	sleepDuration := 250 * time.Millisecond
	for attempt := 1; attempt <= 5; attempt++ {
		// Ensure socket is initialized
		if a.client.Conn == nil {
			log.Printf("[AgentClient] Socket is closed/nil. Reconnecting (attempt %d/5)...", attempt)
			if err = a.client.Connect(); err != nil {
				log.Printf("[AgentClient] Reconnect failed: %v", err)
				if attempt == 5 {
					break
				}
				time.Sleep(sleepDuration)
				sleepDuration *= 2
				continue
			}
		}

		result, err = op()
		if err == nil {
			return result, nil
		}

		log.Printf("[AgentClient] SNMP request failed (attempt %d/5): %v", attempt, err)
		if attempt < 5 {
			log.Println("[AgentClient] Closing broken socket and retrying...")
			if a.client.Conn != nil {
				a.client.Conn.Close()
				a.client.Conn = nil
			}
			time.Sleep(sleepDuration)
			sleepDuration *= 2
		}
	}
	return nil, fmt.Errorf("all 5 attempts failed to contact agent: %w", err)
}
