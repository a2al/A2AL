# Deploy A2AL on Windows

Two paths: **built-in service install** (recommended) and **manual Task Scheduler XML**
(for custom paths or scripted deployment).

Data directory: `%APPDATA%\a2al\`

---

## Path A — Built-in service install (recommended)

Download `a2al_<version>_windows_amd64.zip` from [Releases](https://github.com/a2al/a2al/releases) and extract it.

```powershell
.\a2ald.exe service install
```

The installer copies `a2ald.exe` to `%ProgramFiles%\A2AL\` and adds it to the system PATH — open a new terminal after install and use `a2ald` directly. The downloaded copy can be deleted.

Already using Node.js? `npm install -g a2ald` is an alternative that also places `a2ald` on PATH; then run `a2ald service install`.

If this terminal already has administrator rights, that installs a Windows Service
(survives reboot, no login required) and starts it.

If not, and stdin is a terminal, a menu appears:

```
[1] System Service  — UAC prompt; survives reboot (recommended for a machine that stays on)
[2] Task Scheduler  — no elevation; starts at login, stops when you log out
```

Skip the menu:

```powershell
.\a2ald.exe service install -user    # Task Scheduler; stops at logout
```

(`-user` installs to `%LocalAppData%\A2AL\` and adds it to the user PATH.)

Manage (in a new terminal, or after PATH has refreshed):

```powershell
a2ald service status
a2ald service stop
a2ald service start
a2ald service uninstall
```

---

## Path B — Manual Task Scheduler XML (scripted / custom path)

Use this for unattended deployment or when `a2ald` is not in the system PATH.

```powershell
# If a2ald is not in PATH, edit a2ald-task.xml first:
# Change <Command>a2ald</Command> to <Command>C:\path\to\a2ald.exe</Command>

schtasks /create /tn "A2AL Daemon" /xml "$PWD\a2ald-task.xml" /f
schtasks /run    /tn "A2AL Daemon"
```

Verify:

```powershell
schtasks /query /tn "A2AL Daemon" /fo LIST
```

Manage:

```powershell
schtasks /end    /tn "A2AL Daemon"        # stop
schtasks /run    /tn "A2AL Daemon"        # start
schtasks /change /tn "A2AL Daemon" /disable   # disable autostart
schtasks /delete /tn "A2AL Daemon" /f    # remove
```

Logs: `%APPDATA%\a2al\a2ald.log` (see `log_file` in `config.toml`).

---

## Configuration

Edit config while the service is stopped:

```powershell
a2ald service stop
notepad "$env:APPDATA\a2al\config.toml"
a2ald service start
```

---

## Uninstall

```powershell
a2ald service uninstall
# Optional: remove data and keys
Remove-Item -Recurse -Force "$env:APPDATA\a2al"
```

If installed via Path B:

```powershell
schtasks /end    /tn "A2AL Daemon"
schtasks /delete /tn "A2AL Daemon" /f
Remove-Item -Recurse -Force "$env:APPDATA\a2al"   # optional
```
