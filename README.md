# twsnmpv3proxy

English | [日本語](README_ja.md)

A proxy server designed to bridge standard Windows SNMP agents (or any existing SNMPv2c agents) to support secure SNMPv3 communications.

It receives and decrypts/authenticates SNMPv3 requests from SNMPv3 managers, translates them to corresponding SNMPv2c requests, and forwards them to the underlying SNMPv2c agents.

## Features

- **SNMPv3 to SNMPv2c Translation**: Seamlessly proxies between secure SNMPv3 (USM model) and SNMPv2c.
- **SNMPv3 AuthPriv Support (Highest Security)**: Supports MD5/SHA/SHA256/SHA384/SHA512 authentication and DES/AES/AES192/AES256/AES192C/AES256C encryption (conforming to gosnmp supported algorithms).
- **SNMPv3 Discovery Support**: Properly responds to EngineID discovery requests with `Report` PDUs.
- **Major SNMP Operations**: Supports `GET`, `GETNEXT`, and `GETBULK` requests.
- **Automatic Connection Recovery**: Recreates sockets and retries requests (up to 5 times with exponential backoff) if communication errors (like broken pipe) occur with the SNMPv2c agent.
- **Windows Service Support**: Can be installed, started, stopped, and uninstalled as a native Windows service.
- **Automatic EngineID Generation & Persistence**: If not configured, automatically generates a secure EngineID using enterprise number `17862` + random values, and persists it along with the boot counter (`v3_engine_boots`) back to the configuration file (`config.ini`) across restarts.

---

## Quick Start (Integration Test Mode)

Run with the `-test` flag to start a **self-contained integration test**.
This concurrently spins up a mock SNMPv2c agent on port 1162 and the SNMPv3 proxy on port 1161, runs automated test queries, and verifies the results.

```bash
# Run integration test
go run . -test
```

---

## CLI Options

```bash
twsnmpv3proxy [options]
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `-config` | `config.ini` | Path to the INI configuration file. Relative paths are resolved relative to the executable's directory. |
| `-port` | (Overrides config) | SNMPv3 proxy listening UDP port. (e.g., `1161`) |
| `-agent` | `127.0.0.1:161` | Target SNMPv2c agent address (host:port). |
| `-community` | (Overrides config) | Target SNMPv2c agent community name. (e.g., `public`) |
| `-user` | (Overrides config) | SNMPv3 USM username. |
| `-auth-pass` | (Overrides config) | SNMPv3 authentication passphrase (AuthPassphrase). |
| `-priv-pass` | (Overrides config) | SNMPv3 privacy passphrase (PrivPassphrase). |
| `-auth-proto` | (Overrides config) | Authentication protocol (`MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `NoAuth`). |
| `-priv-proto` | (Overrides config) | Privacy protocol (`DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`, `NoPriv`). |
| `-engine-id` | (Overrides config) | SNMPv3 EngineID (Hex string). Automatically generated if left empty. |
| `-local-ip` | (Empty) | Local IP address to bind to when sending requests from the proxy to the target agent. |
| `-mock` | `false` | Concurrently start a mock SNMPv2c agent on port 1162 for testing. |
| `-test` | `false` | Start in self-contained integration test mode. |
| `-service` | (Empty) | Windows service management command (`install`, `uninstall`, `start`, `stop`). |

※ **Priority**: CLI arguments > Configuration file (`config.ini`) > Default values

---

## Configuration File (`config.ini`)

Create a `config.ini` file based on the template below (or `config.ini.sample`).

```ini
proxy_port = 1161
v3_user = proxyuser
v3_auth_pass = authpassword
v3_priv_pass = privpassword
v3_auth_proto = SHA
v3_priv_proto = AES
v3_engine_id = 
v3_engine_boots = 1
agent_address = 127.0.0.1:161
agent_community = public
```

---

## Running as a Windows Service

Run the following commands in an elevated Command Prompt or PowerShell (Run as Administrator) on Windows.

### 1. Register the Service (Install)
```cmd
twsnmpv3proxy.exe -service install -config C:\\path\\to\\config.ini
```
※ It is highly recommended to specify an absolute path for `-config` to avoid working directory issues when running as a system service.

### 2. Start the Service
```cmd
twsnmpv3proxy.exe -service start
```

### 3. Stop the Service
```cmd
twsnmpv3proxy.exe -service stop
```

### 4. Remove the Service (Uninstall)
```cmd
twsnmpv3proxy.exe -service uninstall
```

---

## Build and Development

This project uses `mise` for environment and task management.

```bash
# Local build
mise run build

# Cross-compile for Windows (exe)
mise run build_windows

# Run unit tests
mise run test

# Run integration tests
mise run integration

# Build Windows release package (ZIP)
mise run package
```

---

## License

See the [LICENSE](LICENSE) file.
