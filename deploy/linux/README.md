# Deploy A2AL on Linux (systemd)

Tested on Ubuntu 22.04 / Debian 12 / CentOS Stream 9. Requires systemd.

## Option A: Install via package (recommended)

Download the `.deb` or `.rpm` from the [latest release](https://github.com/a2al/a2al/releases/latest).

**Debian / Ubuntu:**
```bash
sudo dpkg -i a2al_<version>_amd64.deb
```

**CentOS / RHEL / Fedora:**
```bash
sudo rpm -i a2al-<version>-1.x86_64.rpm
```

The package installs:
- `a2ald` and `a2al` binaries to `/opt/a2al/bin/`
- symlinks at `/usr/local/bin/a2ald` and `/usr/local/bin/a2al`
- systemd service `a2ald` (started automatically on install)

---

## Option B: Manual install from binary

Download the appropriate archive from the [latest release](https://github.com/a2al/a2al/releases/latest) and extract it.

### 1. Place binaries

```bash
sudo mkdir -p /opt/a2al/bin
sudo cp a2ald /opt/a2al/bin/a2ald
sudo cp a2al  /opt/a2al/bin/a2al
sudo chmod +x /opt/a2al/bin/a2ald /opt/a2al/bin/a2al
```

### 2. Set up system user and data directory

```bash
sudo useradd -r -s /bin/false -M -d /opt/a2al a2al
sudo mkdir -p /opt/a2al/data
sudo chown -R a2al:a2al /opt/a2al/data
```

Note: only the data directory is owned by the service user. Binaries remain owned by root.

### 3. Add to PATH (optional)

```bash
sudo ln -sf /opt/a2al/bin/a2ald /usr/local/bin/a2ald
sudo ln -sf /opt/a2al/bin/a2al  /usr/local/bin/a2al
```

### 4. Install and start the service

```bash
sudo cp a2ald.service /etc/systemd/system/a2ald.service
sudo systemctl daemon-reload
sudo systemctl enable --now a2ald
```

On first start, `a2ald` writes a default `config.toml` to `/opt/a2al/data/`.

---

## Option C: Manual build from source

```bash
# Build
GOOS=linux GOARCH=amd64 go build -o a2ald ./cmd/a2ald
GOOS=linux GOARCH=amd64 go build -o a2al  ./cmd/a2al

# For ARM64 (e.g. Raspberry Pi, AWS Graviton):
GOOS=linux GOARCH=arm64 go build -o a2ald ./cmd/a2ald
GOOS=linux GOARCH=arm64 go build -o a2al  ./cmd/a2al
```

Then follow Option B steps from step 1.

---

## Configuration

Edit the config file:
```bash
sudo -u a2al nano /opt/a2al/data/config.toml
```

For a public bootstrap node:
```toml
disable_upnp = true   # no UPnP router on a server
auto_publish = false  # routing-only node; omit to be discoverable as an agent too
log_format   = "json" # optional, better for log aggregators
```

Then restart:
```bash
sudo systemctl restart a2ald
sudo journalctl -u a2ald -f
```

## Firewall

Open the DHT UDP port (default 4121):

Ubuntu / Debian:
```bash
sudo ufw allow 4121/udp
```

CentOS / RHEL (firewalld):
```bash
sudo firewall-cmd --permanent --add-port=4121/udp
sudo firewall-cmd --reload
```

## SELinux (CentOS / RHEL only)

Set the correct file context for the data directory:
```bash
sudo semanage fcontext -a -t var_t '/opt/a2al/data(/.*)?'
sudo restorecon -Rv /opt/a2al/data
```

If `semanage` is not installed:
```bash
sudo dnf install -y policycoreutils-python-utils
```

## Register as a bootstrap node (optional)

Add a DNS TXT record for `_a2al-bootstrap.a2al.org`:
```
"<your-public-ip>:4121"
```

Or configure directly in `config.toml`:
```toml
bootstrap = ["<your-public-ip>:4121"]
```

## Management

```bash
sudo systemctl status a2ald       # status
sudo journalctl -u a2ald -f       # live logs
sudo systemctl restart a2ald      # restart
sudo systemctl stop a2ald         # stop
```

## Uninstall

**Via package:**
```bash
sudo dpkg -r a2al       # Debian/Ubuntu
sudo rpm -e a2al        # CentOS/RHEL
```
Data and keys in `/opt/a2al/data/` are preserved. To fully remove:
```bash
sudo rm -rf /opt/a2al/data
sudo userdel a2al
```

**Manual uninstall:**
```bash
sudo systemctl disable --now a2ald
sudo rm /etc/systemd/system/a2ald.service
sudo rm -f /usr/local/bin/a2ald /usr/local/bin/a2al
sudo rm -rf /opt/a2al/bin
sudo rm -rf /opt/a2al/data   # optional, removes keys and config
sudo userdel a2al
```
