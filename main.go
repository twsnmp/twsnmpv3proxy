package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	defaultConfigPath = "config.ini"
	mockAgentPort     = 1162
	mockProxyPort     = 1161
	testOID           = ".1.3.6.1.2.1.1.1.0" // sysDescr
	mockSysDescr      = "Mock SNMPv2c Agent System Description"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Define command-line flags
	configPath := flag.String("config", defaultConfigPath, "Path to INI configuration file")
	proxyPort := flag.Int("port", 0, "SNMPv3 proxy listen port (overrides config)")
	agentAddress := flag.String("agent", "127.0.0.1:161", "Target SNMPv2c agent address (overrides config)")
	agentCommunity := flag.String("community", "", "SNMPv2c community name (overrides config)")
	v3User := flag.String("user", "", "SNMPv3 USM username (overrides config)")
	v3AuthPass := flag.String("auth-pass", "", "SNMPv3 authentication passphrase (overrides config)")
	v3PrivPass := flag.String("priv-pass", "", "SNMPv3 privacy passphrase (overrides config)")
	v3AuthProto := flag.String("auth-proto", "", "SNMPv3 authentication protocol (overrides config, e.g. SHA)")
	v3PrivProto := flag.String("priv-proto", "", "SNMPv3 privacy protocol (overrides config, e.g. AES)")
	v3EngineID := flag.String("engine-id", "", "SNMPv3 EngineID hex string (overrides config)")
	localIP := flag.String("local-ip", "", "Local IP address to bind for outgoing requests")
	startMock := flag.Bool("mock", false, "Start a mock SNMPv2c agent on port 1162 alongside the proxy")
	runTest := flag.Bool("test", false, "Start in self-contained integration test mode")
	serviceCmd := flag.String("service", "", "Windows service command: install, uninstall, start, stop")
	flag.Parse()

	// 1. Check if running under SCM (Windows Service manager)
	if isWindowsService() {
		runService(*configPath, *localIP)
		return
	}

	// 2. Handle Windows Service commands
	if *serviceCmd != "" {
		err := handleServiceCommand(*serviceCmd, *configPath, *localIP)
		if err != nil {
			log.Fatalf("Service command failed: %v", err)
		}
		return
	}

	// 3. Load configuration (try loading config, fallback to default config if config file does not exist)
	var config *Config
	var loadErr error
	config, loadErr = LoadConfig(*configPath)
	if loadErr != nil {
		// If custom config was specified and failed to load, crash
		if *configPath != defaultConfigPath {
			log.Fatalf("Failed to load config file: %v", loadErr)
		}
		// If default config not found, use default struct values
		log.Printf("Config file %s not found. Using default configurations.", *configPath)
		config = DefaultConfig()
	}

	// Track which flags were explicitly set
	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	// 4. Override configuration with CLI flags
	if *proxyPort != 0 {
		config.ProxyPort = *proxyPort
	}
	if setFlags["agent"] {
		config.AgentAddress = *agentAddress
	}
	if *agentCommunity != "" {
		config.AgentCommunity = *agentCommunity
	}
	if *v3User != "" {
		config.V3User = *v3User
	}
	if *v3AuthPass != "" {
		config.V3AuthPass = *v3AuthPass
	}
	if *v3PrivPass != "" {
		config.V3PrivPass = *v3PrivPass
	}
	if *v3AuthProto != "" {
		config.V3AuthProto = *v3AuthProto
	}
	if *v3PrivProto != "" {
		config.V3PrivProto = *v3PrivProto
	}
	if *v3EngineID != "" {
		config.V3EngineID = *v3EngineID
	}

	// Graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	var wg sync.WaitGroup

	// 5. Run in Integration Test Mode if -test flag is specified
	if *runTest {
		log.Println("[Main] Starting self-contained integration test...")

		// Step 1: Start Mock SNMPv2c Agent on port 1162
		wg.Add(1)
		go func() {
			defer wg.Done()
			runMockV2cAgent(ctx, mockAgentPort)
		}()
		time.Sleep(500 * time.Millisecond)

		// Step 2: Configure Proxy targeting the mock agent
		config.ProxyPort = mockProxyPort
		config.AgentAddress = fmt.Sprintf("127.0.0.1:%d", mockAgentPort)
		
		agentClient, err := NewAgentClient(config, *localIP)
		if err != nil {
			log.Fatalf("[Main] Failed to initialize AgentClient: %v", err)
		}
		defer agentClient.Close()

		proxyServer, err := NewProxyServer(config, agentClient, *localIP)
		if err != nil {
			log.Fatalf("[Main] Failed to initialize ProxyServer: %v", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxyServer.Start(ctx); err != nil {
				log.Printf("[ProxyServer] Finished with error: %v", err)
			}
		}()
		time.Sleep(500 * time.Millisecond)

		// Step 3: Run SNMPv3 test client (manager)
		log.Println("[Test] Running integration client query...")
		success := runTestClient(config)

		// Clean up
		cancel()
		wg.Wait()

		if success {
			log.Println("[Test] SUCCESS: Integration test passed successfully!")
			os.Exit(0)
		} else {
			log.Println("[Test] FAILURE: Integration test failed.")
			os.Exit(1)
		}
	}

	// 6. Standalone Proxy Mode
	if *startMock {
		log.Printf("[Main] Starting mock agent alongside proxy on port %d...", mockAgentPort)
		wg.Add(1)
		go func() {
			defer wg.Done()
			runMockV2cAgent(ctx, mockAgentPort)
		}()
		time.Sleep(500 * time.Millisecond)
	}

	agentClient, err := NewAgentClient(config, *localIP)
	if err != nil {
		log.Fatalf("[Main] Failed to initialize AgentClient: %v", err)
	}
	defer agentClient.Close()

	proxyServer, err := NewProxyServer(config, agentClient, *localIP)
	if err != nil {
		log.Fatalf("[Main] Failed to initialize ProxyServer: %v", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := proxyServer.Start(ctx); err != nil {
			log.Printf("[ProxyServer] Stopped with error: %v", err)
		}
	}()

	log.Printf("[Main] Proxy is running. Target Agent: %s.", config.AgentAddress)
	log.Println("[Main] Press Ctrl+C to terminate.")

	// Listen for OS interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("[Main] Stopping server and cleaning up...")
	cancel()
	wg.Wait()
	log.Println("[Main] Proxy stopped.")
}

// runTestClient performs an SNMPv3 query to verify the proxy.
func runTestClient(config *Config) bool {
	authProto, _ := ParseAuthProtocol(config.V3AuthProto)
	privProto, _ := ParsePrivProtocol(config.V3PrivProto)

	manager := &gosnmp.GoSNMP{
		Target:        "127.0.0.1",
		Port:          uint16(config.ProxyPort),
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(3) * time.Second,
		Retries:       2,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 config.V3User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: config.V3AuthPass,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        config.V3PrivPass,
		},
	}

	if config.V3AuthProto == "NoAuth" {
		manager.MsgFlags = gosnmp.NoAuthNoPriv
	} else if config.V3PrivProto == "NoPriv" {
		manager.MsgFlags = gosnmp.AuthNoPriv
	}

	err := manager.Connect()
	if err != nil {
		log.Printf("[Test Client] Connect error: %v", err)
		return false
	}
	defer manager.Conn.Close()

	log.Printf("[Test Client] Sending SNMPv3 GET request for OID %s...", testOID)
	result, err := manager.Get([]string{testOID})
	if err != nil {
		log.Printf("[Test Client] GET request failed: %v", err)
		return false
	}

	for _, variable := range result.Variables {
		log.Printf("[Test Client] Variable received - OID: %s, Type: %s, Value: %s",
			variable.Name, variable.Type.String(), string(variable.Value.([]byte)))
		normalizedName := strings.TrimPrefix(variable.Name, ".")
		if normalizedName == "1.3.6.1.2.1.1.1.0" && string(variable.Value.([]byte)) == mockSysDescr {
			return true
		}
	}

	return false
}

// --- Mock SNMPv2c Agent Implementation ---

var mockMIB = []gosnmp.SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte(mockSysDescr)},
	{Name: ".1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.3.2.10"},
	{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(123456)},
	{Name: ".1.3.6.1.2.1.1.4.0", Type: gosnmp.OctetString, Value: []byte("contact@example.com")},
	{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("mock-agent")},
	{Name: ".1.3.6.1.2.1.1.6.0", Type: gosnmp.OctetString, Value: []byte("Server Room 1")},
	{Name: ".1.3.6.1.2.1.1.7.0", Type: gosnmp.Integer, Value: int(72)},
}

func ensureLeadingDot(oid string) string {
	if !strings.HasPrefix(oid, ".") {
		return "." + oid
	}
	return oid
}

func parseOID(oid string) []int {
	oid = strings.TrimPrefix(oid, ".")
	parts := strings.Split(oid, ".")
	res := make([]int, 0, len(parts))
	for _, p := range parts {
		var val int
		if _, err := fmt.Sscanf(p, "%d", &val); err == nil {
			res = append(res, val)
		}
	}
	return res
}

func compareOIDs(a, b string) int {
	pa := parseOID(a)
	pb := parseOID(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	if len(pa) < len(pb) {
		return -1
	}
	if len(pa) > len(pb) {
		return 1
	}
	return 0
}

func findExactPDU(currentOID string) gosnmp.SnmpPDU {
	for _, m := range mockMIB {
		if compareOIDs(m.Name, currentOID) == 0 {
			return m
		}
	}
	return gosnmp.SnmpPDU{
		Name:  ensureLeadingDot(currentOID),
		Type:  gosnmp.NoSuchInstance,
		Value: nil,
	}
}

func findNextPDU(currentOID string) gosnmp.SnmpPDU {
	for _, m := range mockMIB {
		if compareOIDs(m.Name, currentOID) > 0 {
			return m
		}
	}
	return gosnmp.SnmpPDU{
		Name:  ensureLeadingDot(currentOID),
		Type:  gosnmp.EndOfMibView,
		Value: nil,
	}
}

// runMockV2cAgent simulates a simple SNMPv2c agent.
func runMockV2cAgent(ctx context.Context, port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("[Mock Agent] Error starting UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("[Mock Agent] Listening on UDP %s", addr)

	// Read loop shut down on cancel
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return // normal shutdown
			}
			log.Printf("[Mock Agent] Read error: %v", err)
			continue
		}

		// Decode incoming SNMPv2c request
		gs := &gosnmp.GoSNMP{
			Version:   gosnmp.Version2c,
			Community: "public",
		}
		packet, err := gs.SnmpDecodePacket(buf[:n])
		if err != nil {
			log.Printf("[Mock Agent] Error decoding packet: %v", err)
			continue
		}

		// Prepare SNMPv2c response
		var responseVars []gosnmp.SnmpPDU

		switch packet.PDUType {
		case gosnmp.GetRequest:
			responseVars = make([]gosnmp.SnmpPDU, len(packet.Variables))
			for i, v := range packet.Variables {
				responseVars[i] = findExactPDU(v.Name)
			}

		case gosnmp.GetNextRequest:
			responseVars = make([]gosnmp.SnmpPDU, len(packet.Variables))
			for i, v := range packet.Variables {
				responseVars[i] = findNextPDU(v.Name)
			}

		case gosnmp.GetBulkRequest:
			numNonRepeaters := int(packet.NonRepeaters)
			if numNonRepeaters > len(packet.Variables) {
				numNonRepeaters = len(packet.Variables)
			}

			for i := 0; i < numNonRepeaters; i++ {
				v := packet.Variables[i]
				responseVars = append(responseVars, findNextPDU(v.Name))
			}

			repeaters := packet.Variables[numNonRepeaters:]
			if len(repeaters) > 0 && packet.MaxRepetitions > 0 {
				currentOIDs := make([]string, len(repeaters))
				for i, r := range repeaters {
					currentOIDs[i] = r.Name
				}

				for step := uint32(0); step < packet.MaxRepetitions; step++ {
					for i := range repeaters {
						nextPDU := findNextPDU(currentOIDs[i])
						responseVars = append(responseVars, nextPDU)
						currentOIDs[i] = nextPDU.Name
					}
				}
			}

		default:
			log.Printf("[Mock Agent] Unsupported PDU type: %v", packet.PDUType)
			continue
		}

		responsePacket := &gosnmp.SnmpPacket{
			Version:    gosnmp.Version2c,
			Community:  "public",
			PDUType:    gosnmp.GetResponse,
			RequestID:  packet.RequestID,
			Error:      gosnmp.NoError,
			ErrorIndex: 0,
			Variables:  responseVars,
		}

		respBytes, err := responsePacket.MarshalMsg()
		if err != nil {
			log.Printf("[Mock Agent] Error encoding response: %v", err)
			continue
		}

		_, err = conn.WriteTo(respBytes, clientAddr)
		if err != nil {
			log.Printf("[Mock Agent] Error sending response: %v", err)
		}
	}
}
