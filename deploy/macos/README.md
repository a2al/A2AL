# Deploy A2AL on macOS

Two paths: **built-in service install** (recommended) and **manual plist** (for custom
paths or system-wide setup).

Data directory: `~/Library/Application Support/a2al/`

---

## Path A — Built-in service install (recommended)

Download A2AL for macOS from [Releases](https://github.com/a2al/a2al/releases) and extract it. From that folder:

```bash
./a2ald service install          # writes and loads a launchd user agent; starts immediately
```

The binary is copied to `~/Library/Application Support/A2AL/` — the downloaded copy can be deleted afterwards. Logs go to `~/Library/Logs/a2ald.log`.

For convenient management, add the install directory to your PATH (one-time):

```bash
echo 'export PATH="$HOME/Library/Application Support/A2AL:$PATH"' >> ~/.zprofile
source ~/.zprofile       # or open a new terminal
```

Prefer a package manager? `npm install -g a2ald` installs and places `a2ald` on PATH automatically; then run `a2ald service install`.

Manage (after PATH is set, or prefix with the full install path):

```bash
a2ald service status
a2ald service stop
a2ald service start
a2ald service uninstall
```

---

## Path B — Manual plist (custom binary path)

Use this when you need to point launchd at a binary that is not the one
`a2ald service install` copies.

The file in this directory is a **user** Launch Agent. It starts at login for that
account; it is not a system Launch Daemon.

Install the binary first (see Path A above), then:

```bash
# Copy and fix the log path placeholder
sed "s|/Users/YOU|$HOME|g" org.a2al.a2ald.plist \
  > ~/Library/LaunchAgents/org.a2al.a2ald.plist

launchctl load ~/Library/LaunchAgents/org.a2al.a2ald.plist
```

If `a2ald` is not at `/usr/local/bin/a2ald`, edit `ProgramArguments` in the plist first:

```xml
<key>ProgramArguments</key>
<array>
    <string>/path/to/a2ald</string>
</array>
```

### Verify

```bash
launchctl list | grep a2al
tail -f ~/Library/Logs/a2ald.log
```

### Manage

```bash
# Unload (stop + disable autostart)
launchctl unload ~/Library/LaunchAgents/org.a2al.a2ald.plist

# Load (start + enable autostart)
launchctl load ~/Library/LaunchAgents/org.a2al.a2ald.plist

# macOS 11+ (Monterey and later)
launchctl stop  org.a2al.a2ald
launchctl start org.a2al.a2ald
```

### Uninstall

```bash
launchctl unload ~/Library/LaunchAgents/org.a2al.a2ald.plist
rm ~/Library/LaunchAgents/org.a2al.a2ald.plist
rm -rf "$HOME/Library/Application Support/a2al"   # optional — removes keys and config
```

---

## Configuration

Edit config while the service is stopped:

```bash
a2ald service stop
nano "$HOME/Library/Application Support/a2al/config.toml"
a2ald service start
```

---

## Build from source

```bash
# Intel Mac
GOOS=darwin GOARCH=amd64 go build -o a2ald ./cmd/a2ald

# Apple Silicon (M1/M2/M3/M4)
GOOS=darwin GOARCH=arm64 go build -o a2ald ./cmd/a2ald
```

Place the binary in your PATH, then follow Path A or B.
