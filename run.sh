#!/usr/bin/env sh
set -e
set -a
source .env
set +a

cleanup() {
    echo "Caught interrupt signal. Stopping Python app (PID $APP_PID)..."
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null
    echo "Cleanup complete. Exiting."
    exit 0
}

trap cleanup SIGINT

# use cloudflare gateway root cert
CERT_PATH="./cert.pem"
if [ -f "$CERT_PATH" ]; then
  export REQUESTS_CA_BUNDLE="$CERT_PATH"
  export CF_CA_BUNDLE="$CERT_PATH"
  export SSL_CERT_FILE="$CERT_PATH"
  export CURL_CA_BUNDLE="$CERT_PATH"
	echo "Using CA bundle at $CERT_PATH for SSL verification"
else
  echo "Warning: CA bundle not found at $CERT_PATH — SSL verification may fail"
fi

# start app
.venv/bin/python3 app.py &
APP_PID=$!
echo "App started w PID: $APP_PID"

sleep 3

cloudflared tunnel run --protocol http2 --token "$CF_TUNNEL_TOKEN" --url "http://127.0.0.1:${PORT}"

cleanup
