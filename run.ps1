#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# --- load .env into this process's environment ---
$envFile = Join-Path $ScriptDir ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { return }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { return }
        $key = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()
        if ($value.Length -ge 2 -and (
            ($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))
        )) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [System.Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
} else {
    Write-Warning "No .env file found at $envFile"
}

# --- use cloudflare gateway root cert, if present ---
$certPath = Join-Path $ScriptDir "cert.pem"
if (Test-Path $certPath) {
    $env:REQUESTS_CA_BUNDLE = $certPath
    $env:CF_CA_BUNDLE = $certPath
    $env:SSL_CERT_FILE = $certPath
    $env:CURL_CA_BUNDLE = $certPath
    Write-Host "Using CA bundle at $certPath for SSL verification"
} else {
    Write-Warning "CA bundle not found at $certPath - SSL verification may fail"
}

# --- start app ---
$pythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    throw "Python venv not found at $pythonExe. Create it first with: python -m venv .venv"
}

try {
    $appProcess = Start-Process -FilePath $pythonExe -ArgumentList "app.py" -WorkingDirectory $ScriptDir -PassThru -NoNewWindow
    Write-Host "App started w PID: $($appProcess.Id)"

    Start-Sleep -Seconds 5

    if (-not $env:CF_TUNNEL_TOKEN) {
        throw "CF_TUNNEL_TOKEN is not set (check .env)"
    }
    cloudflared tunnel run --protocol http2 --token "$env:CF_TUNNEL_TOKEN"
}
finally {
    Write-Host "Caught exit. Stopping Python app (PID $($appProcess.Id))..."
    if ($appProcess -and -not $appProcess.HasExited) {
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Cleanup complete. Exiting."
}
