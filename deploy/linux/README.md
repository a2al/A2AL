# Deploy A2AL on Linux

## Option A — Package install (recommended)

The release publishes `.deb` and `.rpm` packages. The package installer handles
everything: creates the `a2al` system user, creates `/opt/a2al/data` and
`/opt/a2al/files`, installs the systemd unit, and starts the service.

**Debian / Ubuntu:**
```bash
sudo dpkg -i a2al_<version>_amd64.deb
```

**CentOS / RHEL / Fedora:**
```bash
sudo rpm -i a2al-<version>-1.x86_64.rpm
```

**ARM64 (Raspberry Pi, AWS Graviton, …):**
Replace `amd64` with `arm64` (deb) or `aarch64` (rpm).

Download from: https://github.com/a2al/a2al/releases

After install:
- Config: `/opt/a2al/data/config.toml` (written on first start if absent)
- Data/keys: `/opt/a2al/data/`
- File sandbox: `/opt/a2al/files/`
- Binaries: `/opt/a2al/bin/` (symlinked from `/usr/local/bin/`)

---

## Option B — Manual binary + systemd (system-wide service)

Use this when the package is not available or you need a custom setup.

### 1. Install binaries

```bash
sudo mkdir -p /opt/a2al/bin
sudo cp a2ald a2al /opt/a2al/bin/
sudo chmod +x /opt/a2al/bin/a2ald /opt/a2al/bin/a2al
sudo ln -sf /opt/a2al/bin/a2ald /usr/local/bin/a2ald
sudo ln -sf /opt/a2al/bin/a2al  /usr/local/bin/a2al
```

### 2. Create service user and directories

```bash
sudo useradd -r -s /bin/false -M -d /opt/a2al a2al
sudo mkdir -p /opt/a2al/data /opt/a2al/files
sudo chown -R a2al:a2al /opt/a2al/data /opt/a2al/files
```

### 3. Install the systemd unit

The `a2ald.service` file is in this directory:

```bash
sudo cp a2ald.service /etc/systemd/system/a2ald.service
sudo systemctl daemon-reload
sudo systemctl enable --now a2ald
```

---

## Option C — User-level systemd (no root)

For personal workstations where you do not have root and want `a2ald` to start
when you log in. Default data directory: `~/.config/a2al/`.

Create a user unit:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/a2ald.service <<'EOF'
[Unit]
Description=A2AL Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/a2ald
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now a2ald
```

Adjust `ExecStart` to the actual binary path (`which a2ald`).

Logs: `journalctl --user -u a2ald -f`

Enable lingering so the unit runs even when you are logged out:

```bash
loginctl enable-linger $USER
```

---

## Configuration

Edit the config while the service is stopped:

```bash
# System service:
sudo systemctl stop a2ald
sudo -u a2al nano /opt/a2al/data/config.toml
sudo systemctl start a2ald

# User service:
systemctl --user stop a2ald
nano ~/.config/a2al/config.toml
systemctl --user start a2ald
```

For a public routing node (no personal agent identity):

```toml
disable_upnp = true    # no UPnP router on a server
auto_publish  = false  # skip automatic endpoint publishing
log_format    = "json" # better for log aggregators
```

---

## Firewall

Open the DHT UDP port (default 4121):

```bash
# UFW (Ubuntu / Debian)
sudo ufw allow 4121/udp

# firewalld (CentOS / RHEL / Fedora)
sudo firewall-cmd --permanent --add-port=4121/udp
sudo firewall-cmd --reload
```

---

## SELinux (CentOS / RHEL only)

```bash
sudo semanage fcontext -a -t var_t '/opt/a2al/data(/.*)?'
sudo restorecon -Rv /opt/a2al/data
# If semanage is missing:
sudo dnf install -y policycoreutils-python-utils
```

---

## Management

```bash
# System service
sudo systemctl status a2ald
sudo journalctl -u a2ald -f
sudo systemctl restart a2ald
sudo systemctl stop a2ald

# User service
systemctl --user status a2ald
journalctl --user -u a2ald -f
```

---

## MCP client config (HTTP mode)

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

---

## Uninstall

**Via package:**
```bash
sudo dpkg -r a2al       # Debian/Ubuntu
sudo rpm -e a2al        # CentOS/RHEL
# Data and keys in /opt/a2al/data/ are preserved by the package scripts.
# To fully remove:
sudo rm -rf /opt/a2al/data
sudo userdel a2al
```

**Manual:**
```bash
sudo systemctl disable --now a2ald
sudo rm /etc/systemd/system/a2ald.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/a2ald /usr/local/bin/a2al
sudo rm -rf /opt/a2al/bin
sudo rm -rf /opt/a2al/data   # optional — removes keys and config
sudo userdel a2al
```

---

## Build from source

```bash
# amd64
GOOS=linux GOARCH=amd64 go build -o a2ald ./cmd/a2ald
GOOS=linux GOARCH=amd64 go build -o a2al  ./cmd/a2al

# arm64
GOOS=linux GOARCH=arm64 go build -o a2ald ./cmd/a2ald
GOOS=linux GOARCH=arm64 go build -o a2al  ./cmd/a2al
```

Then follow Option B from step 1.
