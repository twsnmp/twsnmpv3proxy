package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// Config holds all the parameters needed to run the SNMPv3-to-v2c proxy.
type Config struct {
	ProxyPort      int    `json:"proxy_port"`
	V3User         string `json:"v3_user"`
	V3AuthPass     string `json:"v3_auth_pass"`
	V3PrivPass     string `json:"v3_priv_pass"`
	V3AuthProto    string `json:"v3_auth_proto"` // MD5, SHA, SHA224, SHA256, SHA384, SHA512, NoAuth
	V3PrivProto    string `json:"v3_priv_proto"` // DES, AES, AES192, AES256, AES192C, AES256C, NoPriv
	V3EngineID     string `json:"v3_engine_id"`  // Hex string, optional
	V3EngineBoots  uint32 `json:"v3_engine_boots"`
	AgentAddress   string `json:"agent_address"`   // Host:Port, e.g. "127.0.0.1:161"
	AgentCommunity string `json:"agent_community"` // v2c community, e.g. "public"
}

// DefaultConfig returns a configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		ProxyPort:      161,
		V3User:         "proxyuser",
		V3AuthPass:     "authpassword",
		V3PrivPass:     "privpassword",
		V3AuthProto:    "SHA",
		V3PrivProto:    "AES",
		V3EngineID:     "",
		V3EngineBoots:  1,
		AgentAddress:   "127.0.0.1:161",
		AgentCommunity: "public",
	}
}

// LoadConfig reads a JSON configuration file and returns a Config struct.
func LoadConfig(path string) (*Config, error) {
	resolvedPath := ResolvePath(path)
	
	file, err := os.Open(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %s (resolved: %s): %w", path, resolvedPath, err)
	}
	defer file.Close()

	config := DefaultConfig()
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to decode JSON config: %w", err)
	}

	return config, nil
}

// ResolvePath converts a relative path to an absolute path relative to the executable's directory.
// If the path is already absolute, it returns the path unchanged.
func ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	execPath, err := os.Executable()
	if err != nil {
		return path
	}
	return filepath.Join(filepath.Dir(execPath), path)
}

// ParseAuthProtocol maps a string to a gosnmp.SnmpV3AuthProtocol.
func ParseAuthProtocol(proto string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(proto) {
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	case "NOAUTH", "":
		return gosnmp.NoAuth, nil
	default:
		return gosnmp.NoAuth, fmt.Errorf("unsupported authentication protocol: %s", proto)
	}
}

// ParsePrivProtocol maps a string to a gosnmp.SnmpV3PrivProtocol.
func ParsePrivProtocol(proto string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(proto) {
	case "DES":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	case "NOPRIV", "":
		return gosnmp.NoPriv, nil
	default:
		return gosnmp.NoPriv, fmt.Errorf("unsupported privacy protocol: %s", proto)
	}
}

// GenerateEngineID generates an authoritative engine ID using enterprise number 17862
// and random bytes as specified.
// Format: 800045c6 (enterprise 17862) + 05 (format: octets) + 8 bytes of random data (16 hex characters).
func GenerateEngineID() (string, error) {
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes for EngineID: %w", err)
	}
	
	// Enterprise number 17862 in hex is 000045c6.
	// Most significant bit set is 800045c6.
	// 5th octet format is 05 (randomly/locally defined octets).
	engineID := "800045c605" + hex.EncodeToString(randomBytes)
	return engineID, nil
}
