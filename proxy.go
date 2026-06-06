package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/slayercat/GoSNMPServer"
)

// ProxyServer handles receiving SNMPv3 requests, translating them to SNMPv2c,
// and returning SNMPv3 responses.
type ProxyServer struct {
	config      *Config
	agentClient *AgentClient
	engineID    GoSNMPServer.SNMPEngineID
	localIP     string
}

// NewProxyServer creates a new ProxyServer instance.
func NewProxyServer(config *Config, agentClient *AgentClient, localIP string) (*ProxyServer, error) {
	// If EngineID is empty, generate one
	if config.V3EngineID == "" {
		eid, err := GenerateEngineID()
		if err != nil {
			return nil, fmt.Errorf("failed to auto-generate EngineID: %w", err)
		}
		config.V3EngineID = eid
		log.Printf("[ProxyServer] Auto-generated EngineID: %s", eid)
	}

	// Increment engine boots
	config.V3EngineBoots++
	log.Printf("[ProxyServer] SNMPv3 Engine Boots incremented to: %d", config.V3EngineBoots)

	// Save the updated Engine ID and Boots to configuration
	if err := config.SaveEngineState(); err != nil {
		log.Printf("[ProxyServer] Warning: failed to persist engine state: %v", err)
	}

	return &ProxyServer{
		config:      config,
		agentClient: agentClient,
		engineID:    GoSNMPServer.SNMPEngineID{EngineIDData: config.V3EngineID},
		localIP:     localIP,
	}, nil
}

// Start runs the UDP listener loop for SNMPv3 requests.
func (p *ProxyServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", p.config.ProxyPort)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP proxy listener on %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("[ProxyServer] Listening for SNMPv3 requests on UDP %s", addr)

	// Close listener on context cancellation
	go func() {
		<-ctx.Done()
		log.Println("[ProxyServer] Context cancelled. Closing proxy listener socket.")
		conn.Close()
	}()

	// Parse security protocols
	authProto, err := ParseAuthProtocol(p.config.V3AuthProto)
	if err != nil {
		return fmt.Errorf("auth protocol error: %w", err)
	}
	privProto, err := ParsePrivProtocol(p.config.V3PrivProto)
	if err != nil {
		return fmt.Errorf("priv protocol error: %w", err)
	}

	engineBytes := p.engineID.Marshal()
	engineBoots := p.config.V3EngineBoots
	if engineBoots == 0 {
		engineBoots = 1
	}

	// Define SNMPv3 USM Parameters
	usmParams := &gosnmp.UsmSecurityParameters{
		UserName:                 p.config.V3User,
		AuthenticationProtocol:   authProto,
		AuthenticationPassphrase: p.config.V3AuthPass,
		PrivacyProtocol:          privProto,
		PrivacyPassphrase:        p.config.V3PrivPass,
		AuthoritativeEngineID:    string(engineBytes),
		AuthoritativeEngineBoots: engineBoots,
		AuthoritativeEngineTime:  uint32(time.Now().Unix()),
	}

	// Compute USM keys
	if authProto != gosnmp.NoAuth {
		GoSNMPServer.GenKeys(usmParams)
	}

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil // normal shutdown
			}
			log.Printf("[ProxyServer] Read error: %v", err)
			continue
		}

		// Spawn a goroutine to process the packet concurrently
		go p.handlePacket(conn, clientAddr, buf[:n], usmParams, engineBytes, engineBoots)
	}
}

func (p *ProxyServer) handlePacket(conn net.PacketConn, clientAddr net.Addr, data []byte, usmParams *gosnmp.UsmSecurityParameters, engineBytes []byte, engineBoots uint32) {
	// 1. Initial Decode to extract SNMP version and parameters
	vhandle := gosnmp.GoSNMP{}
	vhandle.SecurityParameters = &gosnmp.UsmSecurityParameters{
		AuthoritativeEngineID:    string(engineBytes),
		AuthoritativeEngineBoots: engineBoots,
		AuthoritativeEngineTime:  uint32(time.Now().Unix()),
	}

	packet, decodeErr := vhandle.SnmpDecodePacket(data)
	if packet == nil {
		log.Printf("[ProxyServer] Failed to decode packet: %v", decodeErr)
		return
	}

	if packet.Version != gosnmp.Version3 {
		log.Printf("[ProxyServer] Unsupported SNMP version: %v from %s", packet.Version, clientAddr)
		return
	}

	// 2. Check if this is an SNMPv3 Discovery request
	// Discovery packets typically have empty variables, or NoAuthNoPriv with empty engineID.
	isDiscovery := false
	if decodeErr == nil && len(packet.Variables) == 0 {
		isDiscovery = true
	} else {
		// If auth failed or it's a discovery request, check if the engineID in the packet is empty (discovery phase 1)
		if usp, ok := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
			if len(usp.AuthoritativeEngineID) == 0 {
				isDiscovery = true
			}
		}
	}

	if isDiscovery {
		log.Printf("[ProxyServer] Received SNMPv3 Discovery request from %s. Responding with EngineID...", clientAddr)
		reportPacket := &gosnmp.SnmpPacket{
			Version:         gosnmp.Version3,
			PDUType:         gosnmp.Report,
			MsgFlags:        gosnmp.NoAuthNoPriv,
			SecurityModel:   gosnmp.UserSecurityModel,
			RequestID:       packet.RequestID,
			MsgID:           packet.MsgID,
			ContextEngineID: string(engineBytes),
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				AuthoritativeEngineID:    string(engineBytes),
				AuthoritativeEngineBoots: engineBoots,
				AuthoritativeEngineTime:  uint32(time.Now().Unix()),
			},
			Variables: []gosnmp.SnmpPDU{
				{
					Name:  "1.3.6.1.6.3.15.1.1.4.0", // usmStatsUnknownEngineIDs
					Type:  gosnmp.Counter32,
					Value: uint32(0),
				},
			},
		}

		respBytes, err := reportPacket.MarshalMsg()
		if err != nil {
			log.Printf("[ProxyServer] Error marshalling discovery report: %v", err)
			return
		}
		_, err = conn.WriteTo(respBytes, clientAddr)
		if err != nil {
			log.Printf("[ProxyServer] Error sending discovery report: %v", err)
		}
		return
	}

	// 3. For authenticated/encrypted requests, decrypt using full USM parameters
	if decodeErr != nil {
		vhandle.SecurityParameters = usmParams
		var err error
		packet, err = vhandle.SnmpDecodePacket(data)
		if err != nil {
			log.Printf("[ProxyServer] Decryption/Authentication failed for request from %s: %v", clientAddr, err)
			// Print out the incoming packet info for debugging if available
			if usp, ok := vhandle.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
				log.Printf("[ProxyServer] Decrypt debug info - User: %s, AuthProto: %s, PrivProto: %s, EngineID: %s",
					usp.UserName, p.config.V3AuthProto, p.config.V3PrivProto, hex.EncodeToString([]byte(usp.AuthoritativeEngineID)))
			}
			return
		}
	}

	log.Printf("[ProxyServer] Authenticated SNMPv3 request received. PDU Type: %v, RequestID: %d", packet.PDUType, packet.RequestID)

	// 4. Translate and forward to SNMPv2c Agent
	var oids []string
	for _, v := range packet.Variables {
		oids = append(oids, strings.TrimPrefix(v.Name, "."))
	}

	log.Printf("[ProxyServer -> Agent] Querying SNMPv2c agent for OIDs: %v", oids)
	var v2cResult *gosnmp.SnmpPacket
	var err error

	switch packet.PDUType {
	case gosnmp.GetRequest:
		v2cResult, err = p.agentClient.Get(oids)
	case gosnmp.GetNextRequest:
		v2cResult, err = p.agentClient.GetNext(oids)
	case gosnmp.GetBulkRequest:
		v2cResult, err = p.agentClient.GetBulk(oids, packet.NonRepeaters, packet.MaxRepetitions)
	default:
		log.Printf("[ProxyServer] Unsupported proxy PDU type: %v", packet.PDUType)
		return
	}

	if err != nil {
		log.Printf("[ProxyServer] Error forwarding request to v2c agent: %v", err)
		// Send back a GenErr response if communication with target agent failed
		p.sendErrorResponse(conn, clientAddr, packet, usmParams, engineBytes, engineBoots, gosnmp.GenErr)
		return
	}

	// 5. Construct SNMPv3 response
	responsePacket := &gosnmp.SnmpPacket{
		Version:         gosnmp.Version3,
		PDUType:         gosnmp.GetResponse,
		SecurityModel:   gosnmp.UserSecurityModel,
		RequestID:       packet.RequestID,
		MsgID:           packet.MsgID,
		ContextEngineID: string(engineBytes),
		Error:           v2cResult.Error,
		ErrorIndex:      v2cResult.ErrorIndex,
		Variables:       v2cResult.Variables,
	}

	// Prepare response security parameters
	respUsm := usmParams.Copy().(*gosnmp.UsmSecurityParameters)
	respUsm.AuthoritativeEngineTime = uint32(time.Now().Unix())
	if p.config.V3AuthProto != "NoAuth" {
		GoSNMPServer.GenKeys(respUsm)
		if p.config.V3PrivProto != "NoPriv" {
			GoSNMPServer.GenSalt(respUsm)
		}
	}

	responsePacket.SecurityParameters = respUsm
	responsePacket.MsgFlags = packet.MsgFlags // Match manager's security level (AuthPriv/AuthNoPriv/NoAuthNoPriv)

	respBytes, err := responsePacket.MarshalMsg()
	if err != nil {
		log.Printf("[ProxyServer] Error marshalling SNMPv3 response: %v", err)
		return
	}

	_, err = conn.WriteTo(respBytes, clientAddr)
	if err != nil {
		log.Printf("[ProxyServer] Error sending SNMPv3 response to manager: %v", err)
	}
}

// sendErrorResponse sends an SNMPv3 error response back to the manager.
func (p *ProxyServer) sendErrorResponse(conn net.PacketConn, clientAddr net.Addr, reqPacket *gosnmp.SnmpPacket, usmParams *gosnmp.UsmSecurityParameters, engineBytes []byte, engineBoots uint32, errStatus gosnmp.SNMPError) {
	responsePacket := &gosnmp.SnmpPacket{
		Version:         gosnmp.Version3,
		PDUType:         gosnmp.GetResponse,
		SecurityModel:   gosnmp.UserSecurityModel,
		RequestID:       reqPacket.RequestID,
		MsgID:           reqPacket.MsgID,
		ContextEngineID: string(engineBytes),
		Error:           errStatus,
		ErrorIndex:      1,
		Variables:       reqPacket.Variables, // echo back requested variables
	}

	respUsm := usmParams.Copy().(*gosnmp.UsmSecurityParameters)
	respUsm.AuthoritativeEngineTime = uint32(time.Now().Unix())
	if p.config.V3AuthProto != "NoAuth" {
		GoSNMPServer.GenKeys(respUsm)
		if p.config.V3PrivProto != "NoPriv" {
			GoSNMPServer.GenSalt(respUsm)
		}
	}

	responsePacket.SecurityParameters = respUsm
	responsePacket.MsgFlags = reqPacket.MsgFlags

	respBytes, err := responsePacket.MarshalMsg()
	if err != nil {
		log.Printf("[ProxyServer] Error marshalling SNMPv3 error response: %v", err)
		return
	}

	_, _ = conn.WriteTo(respBytes, clientAddr)
}
