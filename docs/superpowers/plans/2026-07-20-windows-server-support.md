# Windows Server Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `run.ps1` wrapper so this Gradio/FastAPI SSO uploader can be launched on Windows Server, and fix the one Windows-incompatible code path in the app, without breaking the existing macOS `run.sh` flow.

**Architecture:** `run.ps1` is a line-for-line PowerShell port of `run.sh`: load `.env` into process env vars, set CA-bundle env vars from `cert.pem` if present, start the Python app as a background process, wait 5s, run `cloudflared tunnel` in the foreground, and stop the Python process in a `finally` block on exit/Ctrl+C. Separately, `backend.py`'s `upload()` swaps a hard link (`os.link`, same-volume only) for `shutil.copy` (works across drives/OSes) so uploads don't silently fail on Windows.

**Tech Stack:** PowerShell 5.1+ (Windows Server default), Python 3 (existing `.venv`), no new dependencies.

## Global Constraints

- No automated test suite exists in this repository (confirmed: no `tests/` dir, no pytest in `requirements.txt`). Verification in this plan is manual/inspection-based (syntax checks, smoke scripts, grep) rather than pytest-based TDD — this matches the approved design spec's Testing section.
- `pwsh` (PowerShell Core) is not installed in this dev environment, so `run.ps1` cannot be executed here. Verification is limited to static checks (balanced braces/quotes, `Set-StrictMode`-style review) plus documenting that a real run must happen on a Windows machine with `cloudflared` and `rclone` on `PATH`.
- Do not change `run.sh` or any other macOS behavior — both platforms must keep working (per spec Goal).
- Do not add process supervision, auto-restart, or Windows-Service installation — out of scope per spec.

---

### Task 1: Fix cross-volume hard link in `backend.py`

**Files:**
- Modify: `backend.py:1-13` (imports), `backend.py:193-203` (`upload()` copy loop)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature changes — `upload(files, stored_state)` keeps its existing `tuple[str, list]` return. Later tasks don't depend on this change directly.

- [ ] **Step 1: Add the `shutil` import**

In `backend.py`, the imports block currently reads (lines 1-13):

```python
# backend.py

from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import json
import os
from rclone_python import rclone
import re
import resend
import subprocess
import tempfile
from urllib.parse import quote, unquote
import uuid
```

Add `import shutil` in alphabetical position among the stdlib imports:

```python
# backend.py

from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import json
import os
from rclone_python import rclone
import re
import resend
import shutil
import subprocess
import tempfile
from urllib.parse import quote, unquote
import uuid
```

- [ ] **Step 2: Replace `os.link` with `shutil.copy`**

In `upload()`, find this block (currently around line 193-203):

```python
  uploaded = []  # list of (temp_path, original_filename)
  failures = []
  for temp_path, orig_name in to_upload:
    try:
      # copy to a temp dir with the correct original name so rclone uploads it with the right name
      with tempfile.TemporaryDirectory() as tmp_dir:
        dest_path = os.path.join(tmp_dir, orig_name)
        os.link(temp_path, dest_path)
        rclone.copy(dest_path, upload_dir, ignore_existing=True, args=["--create-empty-src-dirs"])
      uploaded.append((temp_path, orig_name))
    except Exception as e:
      failures.append((orig_name, str(e)))
      print(f"rclone.copy failed for {orig_name}: {e}")
```

Replace `os.link(temp_path, dest_path)` with `shutil.copy(temp_path, dest_path)`:

```python
  uploaded = []  # list of (temp_path, original_filename)
  failures = []
  for temp_path, orig_name in to_upload:
    try:
      # copy to a temp dir with the correct original name so rclone uploads it with the right name
      with tempfile.TemporaryDirectory() as tmp_dir:
        dest_path = os.path.join(tmp_dir, orig_name)
        shutil.copy(temp_path, dest_path)
        rclone.copy(dest_path, upload_dir, ignore_existing=True, args=["--create-empty-src-dirs"])
      uploaded.append((temp_path, orig_name))
    except Exception as e:
      failures.append((orig_name, str(e)))
      print(f"rclone.copy failed for {orig_name}: {e}")
```

- [ ] **Step 3: Verify no other hard-link usage remains**

Run: `grep -n "os.link" backend.py`
Expected: no output (no matches).

- [ ] **Step 4: Verify the file still parses and imports cleanly**

Run: `source .venv/bin/activate && python -m py_compile backend.py && python -c "import backend" && echo OK`
Expected: `OK` printed, no traceback. (`import backend` will run its module-level `load_dotenv()` / `os.getenv()` calls, which is safe — it doesn't touch the network until a function is called.)

- [ ] **Step 5: Smoke-test that `shutil.copy` behaves like the old `os.link` for this use case**

Run:
```bash
python3 -c "
import shutil, tempfile, os
with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dst_dir:
    src = os.path.join(src_dir, 'source.txt')
    with open(src, 'w') as f:
        f.write('hello')
    dest = os.path.join(dst_dir, 'renamed.txt')
    shutil.copy(src, dest)
    assert os.path.exists(dest)
    with open(dest) as f:
        assert f.read() == 'hello'
    print('OK: shutil.copy staged file under new name with correct contents')
"
```
Expected: `OK: shutil.copy staged file under new name with correct contents` printed, no traceback.

- [ ] **Step 6: Commit**

```bash
git add backend.py
git commit -m "fix: use shutil.copy instead of os.link for cross-platform upload staging"
```

---

### Task 2: Add `run.ps1` Windows launch wrapper

**Files:**
- Create: `run.ps1`

**Interfaces:**
- Consumes: `.env` (same keys as `run.sh`: `CF_TUNNEL_TOKEN`, `DESCOPE_ID`, `RCLONE_CONFIG`, `BUCKET`, `RESEND_KEY`), `cert.pem` (optional), `.venv\Scripts\python.exe`, `app.py`, `cloudflared` on `PATH`.
- Produces: nothing consumed by other tasks — this is a standalone entry point parallel to `run.sh`.

- [ ] **Step 1: Write `run.ps1`**

Create `run.ps1` in the project root with this content:

```powershell
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

$appProcess = Start-Process -FilePath $pythonExe -ArgumentList "app.py" -WorkingDirectory $ScriptDir -PassThru -NoNewWindow
Write-Host "App started w PID: $($appProcess.Id)"

Start-Sleep -Seconds 5

try {
    if (-not $env:CF_TUNNEL_TOKEN) {
        throw "CF_TUNNEL_TOKEN is not set (check .env)"
    }
    cloudflared tunnel run --protocol http2 --token $env:CF_TUNNEL_TOKEN
}
finally {
    Write-Host "Caught exit. Stopping Python app (PID $($appProcess.Id))..."
    if ($appProcess -and -not $appProcess.HasExited) {
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Cleanup complete. Exiting."
}
```

- [ ] **Step 2: Static syntax check (balanced braces/parens/quotes)**

`pwsh` is not installed in this dev environment, so the script can't be executed here. Run this brace/paren balance check instead:

```bash
python3 -c "
content = open('run.ps1').read()
for pair in [('{', '}'), ('(', ')')]:
    open_c, close_c = pair
    assert content.count(open_c) == content.count(close_c), f'{open_c}{close_c} mismatch: {content.count(open_c)} vs {content.count(close_c)}'
assert content.count('\"') % 2 == 0, 'unbalanced double quotes'
print('OK: braces/parens/quotes balanced')
"
```
Expected: `OK: braces/parens/quotes balanced` printed.

- [ ] **Step 3: Review against `run.sh` for behavioral parity**

Run: `cat run.sh` and manually diff each step against `run.ps1`: `.env` loading, CA bundle vars, backgrounding the app + PID log line, 5s sleep, `cloudflared tunnel run` args (`--protocol http2 --token ...`), and cleanup-on-exit killing the app PID. Confirm all five behaviors are present in `run.ps1` (they are, per Step 1 above) — this step is a manual read-through, not a command.

- [ ] **Step 4: Document the Windows-only manual verification that still needs to happen**

This cannot be executed in the current (non-Windows, no-`pwsh`) dev environment. Note in the PR/commit description that before relying on `run.ps1` in production, someone must run it on an actual Windows Server with `cloudflared` and `rclone` installed and on `PATH`, and confirm: the app starts, the tunnel connects, and Ctrl+C stops the Python process (check via Task Manager or `Get-Process python`).

- [ ] **Step 5: Commit**

```bash
git add run.ps1
git commit -m "feat: add run.ps1 wrapper for launching on Windows Server"
```

---

### Task 3: Document Windows Server setup in `README.md`

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `run.ps1` (Task 2), the `shutil.copy` fix (Task 1, no user-visible interface change).
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Add a "Windows Server Setup" section**

`README.md` currently ends with (after the macOS Gradio/FastAPI section):

```markdown
run script:

```bash
chmod +x run.sh
./run.sh
```
```

Append a new section after it:

```markdown

## Windows Server Setup

Equivalent setup for running on Windows Server (PowerShell).

### Cloudflare Tunnel

1. Download `cloudflared` for Windows from the [Cloudflare releases page](https://github.com/cloudflare/cloudflared/releases) and ensure `cloudflared.exe` is on `PATH`.
2. Export the same Cloudflare gateway root CA used on macOS to the project directory as `cert.pem` (see the Cloudflare Tunnel section above for how to obtain it).

### rclone

1. Download `rclone` for Windows from [rclone.org/downloads](https://rclone.org/downloads/) and ensure `rclone.exe` is on `PATH`.
2. Run `rclone config` and follow the same steps as the macOS setup above to create the `r2` remote.

### Gradio / FastAPI Web App

Set up and install dependencies:

```powershell
git clone https://github.com/auda/rundle_upload.git
cd rundle_upload
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

Run script:

```powershell
powershell -ExecutionPolicy Bypass -File run.ps1
```
```

- [ ] **Step 2: Verify the section renders and references the right files**

Run: `grep -n "Windows Server Setup\|run.ps1\|cloudflared.exe\|rclone.exe" README.md`
Expected: all four strings found, confirming the section was added and references the correct filenames.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add Windows Server setup instructions"
```
