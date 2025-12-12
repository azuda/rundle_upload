
# Setup

How to set up and run Rundle CDN Uploader on host machine

## SSL Cert

(macOS)

1. Open Keychain Access -> System Roots -> search "cloudflare"
2. Export Cloudflare root CA cert to project dir as `cert.pem`
3. Copy `cert.pem` to `~/.cloudflared/`

## Cloudflare Tunnel

Install cloudflared:

```bash
brew install cloudflared
```

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
- note down access key id and secret access key

install rclone on host `brew install rclone`

- `rclone config`
- create new remote named `r2`
- select `amazon s3 compliant storage providers` storage type
- select `cloudflare` provider
- select manual aws cred input
- copy paste access key id and secret access key from above
- auto select region
- set endpoint to `S3 API` url from cloudflare R2 dashboard
- test remote with `rclone ls r2:canvas-storage/DIGIEXAM`

## Gradio Web App

Setup and install dependencies:

```bash
git clone https://github.com/auda/rundle_upload.git
cd rundle_upload
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Run script:

```bash
chmod +x run.sh
./run.sh
```
