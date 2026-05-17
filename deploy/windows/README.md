# Deploy A2AL on Windows (Task Scheduler)

Runs `a2ald` automatically when you log in, with automatic restart on failure.
No admin rights required. No third-party tools needed.

---

## Install

### Step 1 — Install `a2ald`

**npm (recommended):**
```powershell
npm install -g a2ald
```

**Binary download:**
Download `a2ald_windows_amd64.zip` from [Releases](https://github.com/a2al/a2al/releases), extract, and place `a2ald.exe` somewhere in your `PATH` (e.g. `C:\Tools\`).

Verify:
```powershell
a2ald --version
```

### Step 2 — Register the scheduled task

Open **PowerShell** (no admin needed) and run:

```powershell
schtasks /create /tn "A2AL Daemon" /xml "$PWD\a2ald-task.xml" /f
```

> If `a2ald` is not in your `PATH`, edit `a2ald-task.xml` first and replace `<Command>a2ald</Command>` with the full path, e.g. `<Command>C:\Tools\a2ald.exe</Command>`.

### Step 3 — Start immediately (without logging out)

```powershell
schtasks /run /tn "A2AL Daemon"
```

---

## Verify

```powershell
schtasks /query /tn "A2AL Daemon" /fo LIST
```

Or call `a2al_status` via MCP and confirm `network_ready: true` (takes ~60–120 s on first run while DHT peers connect).

Logs go to `%USERPROFILE%\.a2al\a2ald.log` by default (check `config.toml` for the exact path).

---

## Management

```powershell
# Stop
schtasks /end /tn "A2AL Daemon"

# Start
schtasks /run /tn "A2AL Daemon"

# Disable (survives reboot but won't start automatically)
schtasks /change /tn "A2AL Daemon" /disable

# Remove entirely
schtasks /delete /tn "A2AL Daemon" /f
```

---

## Data directory

On first start, `a2ald` creates `%USERPROFILE%\.a2al\` for keys and `config.toml`.

To use a custom directory, add arguments in `a2ald-task.xml`:

```xml
<Actions Context="Author">
  <Exec>
    <Command>a2ald</Command>
    <Arguments>-data-dir C:\a2al-data</Arguments>
  </Exec>
</Actions>
```

Then re-import the task:
```powershell
schtasks /delete /tn "A2AL Daemon" /f
schtasks /create /tn "A2AL Daemon" /xml "$PWD\a2ald-task.xml" /f
```

---

## MCP client config (HTTP mode — recommended when running as a service)

Once `a2ald` is running as a background task, point MCP clients at the HTTP endpoint instead of using `--mcp-stdio`:

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

```powershell
schtasks /end    /tn "A2AL Daemon"
schtasks /delete /tn "A2AL Daemon" /f
# Optional: remove data and keys
Remove-Item -Recurse -Force "$env:USERPROFILE\.a2al"
```
