# Deploy a2ald on Linux (systemd)

Tested on Ubuntu 22.04 / Debian 12 / CentOS Stream 9. Requires systemd.

## 1. Build the binary

On any machine with Go installed:

```bash
GOOS=linux GOARCH=amd64 go build -o a2ald ./cmd/a2ald
```

For ARM64 (e.g. Raspberry Pi, AWS Graviton):

```bash
GOOS=linux GOARCH=arm64 go build -o a2ald ./cmd/a2ald
```

## 2. Set up directories and user

```bash
sudo mkdir -p /opt/a2al/bin /opt/a2al/data
sudo cp a2ald /opt/a2al/bin/a2ald
sudo chmod +x /opt/a2al/bin/a2ald
sudo useradd -r -s /bin/false -M -d /opt/a2al a2al
sudo chown -R a2al:a2al /opt/a2al
```

## 3. Install and start the service

```bash
sudo cp a2ald.service /etc/systemd/system/a2ald.service
sudo systemctl daemon-reload
sudo systemctl enable --now a2ald
```

On first start a2ald writes a default `config.toml` to `/opt/a2al/data/`.

## 4. Adjust config (bootstrap node)

```bash
sudo -u a2al nano /opt/a2al/data/config.toml
```

For a public bootstrap node, change:

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

## 5. Open firewall

Ubuntu / Debian:
```bash
sudo ufw allow 4121/udp
```

CentOS / RHEL (firewalld):
```bash
sudo firewall-cmd --permanent --add-port=4121/udp
sudo firewall-cmd --reload
```

## 5a. SELinux (CentOS / RHEL only)

CentOS 9 runs SELinux in Enforcing mode by default. Set the correct file context for the data directory so the service can write to it:

```bash
sudo semanage fcontext -a -t var_t '/opt/a2al/data(/.*)?'
sudo restorecon -Rv /opt/a2al/data
```

If `semanage` is not installed:
```bash
sudo dnf install -y policycoreutils-python-utils
```

## 6. Register as a bootstrap node (optional)

Add a DNS TXT record for `_a2al-bootstrap.a2al.org`:

```
"<your-public-ip>:4121"
```

Other nodes discover this automatically when they have no peers.

Alternatively, operators of private networks can point clients at this node via `config.toml`:

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

```bash
sudo systemctl disable --now a2ald
sudo rm /etc/systemd/system/a2ald.service
sudo rm -rf /opt/a2al
sudo userdel a2al
```
