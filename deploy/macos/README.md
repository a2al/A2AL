# Deploy A2AL on macOS (launchd)

Runs `a2ald` as a **user-level** Launch Agent — starts when you log in, restarts automatically on crash.

---

## Option A: Install via npm (recommended)

```bash
npm install -g a2ald
```

Then install the Launch Agent:

```bash
# Substitute your actual home directory into the log path placeholder
sed "s|/Users/YOU|$HOME|g" org.a2al.a2ald.plist > ~/Library/LaunchAgents/org.a2al.a2ald.plist
launchctl load ~/Library/LaunchAgents/org.a2al.a2ald.plist
```

The plist expects the binary at `/usr/local/bin/a2ald`. If npm installed it elsewhere (check with `which a2ald`), edit the `ProgramArguments` string accordingly before loading.

Logs are written to `~/Library/Logs/a2ald.log`.

---

## Option B: Manual binary install

```bash
# Download binary
curl -fsSL https://github.com/a2al/a2al/releases/latest/download/a2ald_darwin_amd64.tar.gz | tar xz
sudo mv a2ald /usr/local/bin/
sudo chmod +x /usr/local/bin/a2ald
```

For Apple Silicon (M1/M2/M3):
```bash
curl -fsSL https://github.com/a2al/a2al/releases/latest/download/a2ald_darwin_arm64.tar.gz | tar xz
sudo mv a2ald /usr/local/bin/
sudo chmod +x /usr/local/bin/a2ald
```

Then install the Launch Agent:

```bash
sed "s|/Users/YOU|$HOME|g" org.a2al.a2ald.plist > ~/Library/LaunchAgents/org.a2al.a2ald.plist
launchctl load ~/Library/LaunchAgents/org.a2al.a2ald.plist
```

---

## Verify

```bash
launchctl list | grep a2al         # should show org.a2al.a2ald
tail -f /tmp/a2ald.log             # live logs
```

Or call `a2al_status` via MCP and confirm `network_ready: true` (takes ~60–120 s on first boot while DHT peers connect).

---

## Management

```bash
# Stop
launchctl unload ~/Library/LaunchAgents/org.a2al.a2ald.plist

# Start
launchctl load ~/Library/LaunchAgents/org.a2al.a2ald.plist

# macOS 11+ alternative
launchctl stop  org.a2al.a2ald
launchctl start org.a2al.a2ald
```

---

## Data directory

On first start, `a2ald` creates `~/.a2al/` for keys and `config.toml`. To override:

```xml
<key>ProgramArguments</key>
<array>
    <string>/usr/local/bin/a2ald</string>
    <string>-data-dir</string>
    <string>/Users/yourname/.a2al</string>
</array>
```

---

## MCP client config (HTTP mode — recommended when running as a service)

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

```bash
launchctl unload ~/Library/LaunchAgents/org.a2al.a2ald.plist
rm ~/Library/LaunchAgents/org.a2al.a2ald.plist
sudo rm /usr/local/bin/a2ald
rm -rf ~/.a2al   # optional — removes keys and config
```
