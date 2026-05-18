#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs a2ald as a persistent Windows Service.
.PARAMETER DataDir
    Data directory for a2ald. Defaults to %APPDATA%\a2al.
.PARAMETER Uninstall
    Remove the service instead of installing it.
.PARAMETER User
    Install as Task Scheduler task (no admin required; stops on logout).
#>
param(
    [string]$DataDir = "",
    [switch]$Uninstall,
    [switch]$User
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Find a2ald.exe: check next to this script first, then PATH.
$exe = Join-Path $PSScriptRoot "a2ald.exe"
if (-not (Test-Path $exe)) {
    $found = Get-Command a2ald.exe -ErrorAction SilentlyContinue
    if ($found) { $exe = $found.Source }
    else {
        Write-Error "a2ald.exe not found next to this script or in PATH."
        exit 1
    }
}

$installArgs = @("service")
if ($Uninstall) {
    $installArgs += "uninstall"
} else {
    $installArgs += "install"
    if ($User)    { $installArgs += "--user" }
    if ($DataDir) { $installArgs += @("-data-dir", $DataDir) }
}
& $exe @installArgs
exit $LASTEXITCODE
