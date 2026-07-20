# Windows Server Support Design

## Goal

Allow this project (Gradio + FastAPI SSO uploader, currently launched via `run.sh` on macOS)
to run on Windows Server: add a `run.ps1` wrapper equivalent to `run.sh`, and fix any
Windows-incompatible code paths. Ensure the project can still be run on both platforms to support dev and testing.

## Context

Current launch flow (`run.sh`):
1. `source .env` (via `set -a`) to export env vars to the shell.
2. If `cert.pem` exists, export `REQUESTS_CA_BUNDLE`, `CF_CA_BUNDLE`, `SSL_CERT_FILE`,
   `CURL_CA_BUNDLE` pointing at it (Cloudflare gateway root CA for outbound TLS).
3. Start `.venv/bin/python3 app.py` in the background, capture its PID.
4. Sleep 5s, then run `cloudflared tunnel run --protocol http2 --token "$CF_TUNNEL_TOKEN"`
   in the foreground.
5. On SIGINT (Ctrl+C) or exit, `trap cleanup` kills the backgrounded Python process.

The app itself (`app.py`, `backend.py`, `frontend.py`) is pure Python (FastAPI, Gradio,
Descope SDK, rclone-python, resend, truststore) and mostly OS-agnostic already.

## Approach

### 1. `run.ps1`

A PowerShell script mirroring `run.sh` 1:1, launching cloudflared inline (not as a
Windows Service) — matches how `run.sh` behaves today:

- Parse `.env` manually (split on first `=`, skip blank lines and lines starting with `#`)
  and set each var with `$env:KEY = value` — child processes started afterward (Python,
  cloudflared) inherit these automatically, same as `set -a; source .env`.
- If `cert.pem` exists in the script's directory, set the four CA-bundle env vars to its
  full path; otherwise print a warning, same as `run.sh`.
- Launch `.venv\Scripts\python.exe app.py` as a background process (`Start-Process
  -PassThru` or `Start-Job`), keep a handle to it for cleanup.
- `Start-Sleep -Seconds 5`.
- Run `cloudflared tunnel run --protocol http2 --token $env:CF_TUNNEL_TOKEN` in the
  foreground (blocks until interrupted).
- Wrap the tunnel call in `try { ... } finally { Stop-Process the python process }` so
  Ctrl+C or normal script exit stops the Python app, matching `trap cleanup SIGINT`.

Out of scope: installing cloudflared/rclone as Windows Services, process supervision
(auto-restart), or running as a proper Windows Service — this is a like-for-like port of
the existing interactive `run.sh` flow.

### 2. Python code fix: `backend.py::upload()`

`upload()` currently does:

```python
os.link(temp_path, dest_path)
```

to stage the uploaded temp file under its original filename before calling
`rclone.copy`. `os.link` creates a hard link, which requires the source and destination
to be on the same volume. On Windows Server, Gradio's upload temp directory and
Python's `tempfile.TemporaryDirectory()` could land on different drives (e.g. if `TEMP`
is redirected), causing `os.link` to raise `OSError` — currently swallowed into the
per-file `failures` list with no indication of the real cause.

Fix: replace `os.link` with `shutil.copy(temp_path, dest_path)`, which works across
volumes/drives on both Windows and POSIX. This is a small, local change — no other
behavior changes.

No other OS-specific code (signals, POSIX paths, `chmod`, forking) exists in
`app.py`/`backend.py`/`frontend.py`; the rest of the codebase is already portable.

### 3. README

Add a "Windows Server Setup" section alongside the existing macOS instructions,
covering: installing `cloudflared` and `rclone` for Windows (and ensuring both are on
`PATH`), creating the venv with `python -m venv .venv`, and running `run.ps1` instead of
`run.sh` (e.g. `powershell -ExecutionPolicy Bypass -File run.ps1`).

## Testing

No automated tests exist in this project. Verification will be manual/inspection-based:
- `run.ps1` reviewed for correct `.env` parsing and process lifecycle logic (cannot be
  fully executed end-to-end without a Windows Server + Cloudflare tunnel token in this
  environment).
- The `shutil.copy` change is a drop-in replacement verified by reading the diff and
  reasoning about behavior; existing manual upload flow (macOS) should be re-verified
  after the change to confirm no regression.
