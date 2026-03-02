
# Setup

How to set up and run Rundle CDN Uploader on host machine (macOS)

## Cloudflare Tunnel

1. `brew install cloudflared`
2. open `Keychain Access` -> `System Roots` -> search "cloudflare"
3. export cloudflare root CA cert to project dir as `cert.pem`
4. copy `cert.pem` to `~/.cloudflared/`

<!-- <details>
<summary>Set tunnel to run as a service on system boot:</summary>

```bash
sudo cloudflared service install <token>
```
</details>

<details>
<summary>Manually run tunnel in current terminal session only:</summary>

```bash
cloudflared tunnel run --token <token>
```
</details> -->

## rclone

in cloudflare R2 object storage dashboard:

- create user api token with admin read and write
- write down access key id and secret access key

on host:

- `brew install rclone`
- `rclone config`
- create new remote named `r2`
- select storage type - `amazon s3 compliant storage providers`
- select provider - `cloudflare`
- select aws cred input - `manual`
- copy access key id and secret access key from above
- select region - `auto`
- set endpoint - copy `S3 API` url from cloudflare R2 dashboard
- test remote - `rclone ls r2:canvas-storage/DIGIEXAM`

## Gradio / FastAPI Web App

set up and install dependencies:

```bash
git clone https://github.com/auda/rundle_upload.git
cd rundle_upload
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

run script:

```bash
chmod +x run.sh
./run.sh
```
