package main

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestParseAuthProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected gosnmp.SnmpV3AuthProtocol
		hasError bool
	}{
		{"MD5", gosnmp.MD5, false},
		{"SHA", gosnmp.SHA, false},
		{"sha256", gosnmp.SHA256, false},
		{"NoAuth", gosnmp.NoAuth, false},
		{"invalid", gosnmp.NoAuth, true},
	}

	for _, tc := range tests {
		res, err := ParseAuthProtocol(tc.input)
		if tc.hasError && err == nil {
			t.Errorf("expected error for input %q, but got nil", tc.input)
		}
		if !tc.hasError && err != nil {
			t.Errorf("unexpected error for input %q: %v", tc.input, err)
		}
		if res != tc.expected {
			t.Errorf("for input %q, expected %v, but got %v", tc.input, tc.expected, res)
		}
	}
}

func TestParsePrivProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected gosnmp.SnmpV3PrivProtocol
		hasError bool
	}{
		{"DES", gosnmp.DES, false},
		{"AES", gosnmp.AES, false},
		{"aes256", gosnmp.AES256, false},
		{"NoPriv", gosnmp.NoPriv, false},
		{"invalid", gosnmp.NoPriv, true},
	}

	for _, tc := range tests {
		res, err := ParsePrivProtocol(tc.input)
		if tc.hasError && err == nil {
			t.Errorf("expected error for input %q, but got nil", tc.input)
		}
		if !tc.hasError && err != nil {
			t.Errorf("unexpected error for input %q: %v", tc.input, err)
		}
		if res != tc.expected {
			t.Errorf("for input %q, expected %v, but got %v", tc.input, tc.expected, res)
		}
	}
}

func TestGenerateEngineID(t *testing.T) {
	id, err := GenerateEngineID()
	if err != nil {
		t.Fatalf("failed to generate EngineID: %v", err)
	}

	if !strings.HasPrefix(id, "800045c605") {
		t.Errorf("expected EngineID to start with '800045c605', got %q", id)
	}

	// Length should be 800045c605 (10 chars) + 8 bytes * 2 hex chars (16 chars) = 26 chars
	if len(id) != 26 {
		t.Errorf("expected EngineID length to be 26, got %d", len(id))
	}

	// The remaining part should be valid hex
	randomPart := id[10:]
	decoded, err := hex.DecodeString(randomPart)
	if err != nil {
		t.Errorf("expected random part %q to be valid hex, but got error: %v", randomPart, err)
	}
	if len(decoded) != 8 {
		t.Errorf("expected random part to represent 8 bytes, got %d", len(decoded))
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tempFile, err := os.CreateTemp("", "config_test_*.ini")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	configContent := `proxy_port = 1234
v3_user = testuser
v3_auth_pass = authpass
v3_priv_pass = privpass
v3_auth_proto = SHA256
v3_priv_proto = AES256
v3_engine_id = 800045c60511223344
v3_engine_boots = 5
agent_address = 10.0.0.1:161
agent_community = private
`

	if _, err := tempFile.Write([]byte(configContent)); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tempFile.Close()

	config, err := LoadConfig(tempFile.Name())
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if config.ProxyPort != 1234 {
		t.Errorf("expected ProxyPort 1234, got %d", config.ProxyPort)
	}
	if config.V3User != "testuser" {
		t.Errorf("expected V3User 'testuser', got %q", config.V3User)
	}
	if config.V3AuthProto != "SHA256" {
		t.Errorf("expected V3AuthProto 'SHA256', got %q", config.V3AuthProto)
	}
	if config.V3PrivProto != "AES256" {
		t.Errorf("expected V3PrivProto 'AES256', got %q", config.V3PrivProto)
	}
	if config.V3EngineID != "800045c60511223344" {
		t.Errorf("expected V3EngineID '800045c60511223344', got %q", config.V3EngineID)
	}
	if config.V3EngineBoots != 5 {
		t.Errorf("expected V3EngineBoots 5, got %d", config.V3EngineBoots)
	}
	if config.AgentAddress != "10.0.0.1:161" {
		t.Errorf("expected AgentAddress '10.0.0.1:161', got %q", config.AgentAddress)
	}
	if config.AgentCommunity != "private" {
		t.Errorf("expected AgentCommunity 'private', got %q", config.AgentCommunity)
	}
}
