# app.py

# sso w magic link source
# https://github.com/benitomartin/gradio-sso-auth-descope

from descope import DescopeClient, DeliveryMethod, AuthException
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, PlainTextResponse
import gradio as gr
import os
from rclone_python import rclone
import resend
from starlette.requests import Request
from urllib.parse import quote
import uuid
import json
import subprocess

load_dotenv()
PROJECT_ID = os.getenv("DESCOPE_ID")
descope_client = DescopeClient(project_id=PROJECT_ID)

RCLONE_CONFIG = os.getenv("RCLONE_CONFIG")
BUCKET = os.getenv("BUCKET")
MGMT_KEY = os.getenv("DESCOPE_MGMT_KEY")
RESEND_KEY = os.getenv("RESEND_KEY")

# change acceptable file formats here
FILE_TYPES = ["audio", ".pdf"]

# css
STYLE = """
#button_colour {
  background-color: #58212E;
  color: white;
  border-color: #58212E;
}
#button_colour:hover {
  background-color: #7A2E42;
}
"""

# ===============================================================================================================================

# fastapi endpoint for verifying magic link

app = FastAPI()

@app.get('/verify')
async def verify_magic_link(request: Request):
  token = request.query_params.get('t')

  if not token:
    return PlainTextResponse("Error: Token is missing from the URL", status_code=400)

  try:
    user_response = descope_client.magiclink.verify(token)

    session_token = user_response.get('sessionToken', {})
    refresh_token = user_response.get('refreshSessionToken', {})

    if isinstance(session_token, dict):
      session_token = session_token.get('jwt')
    if isinstance(refresh_token, dict):
      refresh_token = refresh_token.get('jwt')

    if not session_token:
      return PlainTextResponse("Authentication error: Failed to retrieve session token.", status_code=400)
    if not refresh_token:
      return PlainTextResponse("Authentication error: Failed to retrieve refresh token.", status_code=400)

    redirect_url = f"https://upload.rundle.ab.ca/?t={session_token}&r={refresh_token}"
    return RedirectResponse(url=redirect_url)

  except AuthException as e:
    error_message = str(e)
    if "expired" in error_message.lower() or "invalid" in error_message.lower():
      return PlainTextResponse("This magic link has expired. Please request a new one.", status_code=401)
    return PlainTextResponse(f"Authentication error: {error_message}", status_code=400)
  except Exception as e:
    return PlainTextResponse(f"Error verifying magic link: {str(e)}", status_code=500)

# ===============================================================================================================================

# frontend + handle descope magic link sso

def send_magic_link(email):
  if not email.endswith("@rundle.ab.ca"):
    return "Error: Please use your Rundle email address."

  try:
    descope_client.magiclink.sign_up_or_in(
      method=DeliveryMethod.EMAIL,
      login_id=email,
      uri=f"https://upload.rundle.ab.ca/verify"
    )
    return f"Magic link sent to {email}! Please check your inbox."
  except Exception as e:
    return f"Error sending magic link: {str(e)}"

def get_token_and_update_state(stored_state, request: gr.Request):
  try:
    query_params = dict(request.query_params)

    if query_params:
      token = query_params.get('t')
      if token:
        refresh_token = query_params.get('r', '')

        user_email = ""
        try:
          jwt_response = descope_client.validate_session(token)
          user_email = extract_email_from_jwt(jwt_response)
        except Exception as e:
          print(f"Could not extract email from token: {e}")

        return (
          gr.update(visible=False), # hide login page
          gr.update(visible=True),  # show main page
          f"Successfully logged in!",
          [token, refresh_token, user_email]
        )

  except Exception as e:
    print(f"Error processing request: {e}", exc_info=True)

  print(f"No token in URL, checking stored state...")
  return load_stored_session(stored_state)

# login page content
def create_login_page():
  login_page = gr.Row(visible=True, equal_height=True)
  with login_page:
    with gr.Column(scale=3):
      email = gr.Textbox(label="Enter your email to log in:")
      send_button = gr.Button("Send One-Time Verification Link", elem_id="button_colour")
    with gr.Column(scale=2):
      login_message = gr.Textbox(label="Status", interactive=False)

  return login_page, email, send_button, login_message

# authed actual page content
def create_main_page(stored_state):
  global FILE_TYPES

  with gr.Column(visible=False) as main_page:
    gr.Markdown("# Rundle CDN Uploader")
    gr.Markdown("Turn your files into easily shareable links by uploading them to the Rundle Cloudflare R2 Storage Bucket.")
    with gr.Row(equal_height=True):
      with gr.Column(scale=3):
        files_input = gr.Files(label="Select file(s) to upload...",
                              file_types=FILE_TYPES)
        upload_button = gr.Button("Upload File(s)", elem_id="button_colour")
      with gr.Column(scale=2):
        status_output = gr.Textbox(label="Status")
    output_table = gr.Dataframe(headers=["Filename", "URL"], label="Uploaded Files", datatype=["str", "str"])
    upload_button.click(
      fn=upload,
      inputs=[files_input, stored_state],
      outputs=[status_output, output_table]
    )

    logout_button = gr.Button("Logout", variant="secondary")
  return main_page, logout_button

def load_stored_session(stored_state):
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state
  print(f"Loading session, state_value: {state_value}, type: {type(state_value)}")

  session_token = None
  refresh_token = None
  if isinstance(state_value, list) and len(state_value) > 0:
    session_token = state_value[0] if state_value[0] else None
    refresh_token = state_value[1] if len(state_value) > 1 else None
  print(f"Has session token: {bool(session_token)}, Has refresh token: {bool(refresh_token)}")

  if session_token:
    try:
      jwt_response = descope_client.validate_session(session_token)
      user_email = extract_email_from_jwt(jwt_response)
      print(f"Session validated successfully")

      return (
        gr.update(visible=False),
        gr.update(visible=True),
        f"Welcome back!",
        [session_token, refresh_token, user_email]
      )
    except Exception as e:
      print(f"Session expired or invalid: {str(e)}")

      if refresh_token:
        try:
          print("Attempting to refresh session...")
          refresh_response = descope_client.refresh_session(refresh_token)

          new_session_token = refresh_response.get('sessionToken')
          new_refresh_token = refresh_response.get('refreshToken')

          if isinstance(new_session_token, dict):
            new_session_token = new_session_token.get('jwt')
          if isinstance(new_refresh_token, dict):
            new_refresh_token = new_refresh_token.get('jwt')

          if new_session_token:
            print("Session refreshed successfully")
            user_email = ""
            try:
              jwt_response = descope_client.validate_session(new_session_token)
              user_email = extract_email_from_jwt(jwt_response)
            except Exception as e:
              print(f"Could not extract email after refresh: {e}")

            return (
              gr.update(visible=False),
              gr.update(visible=True),
              f"Session refreshed. Welcome back!",
              [new_session_token, new_refresh_token, user_email]
            )
        except Exception as refresh_error:
          print(f"Failed to refresh session: {str(refresh_error)}")

  return (
    gr.update(visible=True),
    gr.update(visible=False),
    "Your session has expired. Please log in again.",
    ["", ""]
  )

def logout_user(stored_state):
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state

  try:
    if isinstance(state_value, list) and len(state_value) > 0 and state_value[0]:
      token_str = state_value[0]
      if isinstance(token_str, str):
        descope_client.logout_all(token_str)
        print(f"Token invalidated on Descope")
  except AuthException as e:
    print("Failed to log user out of all current sessions.")
    print("Status Code: " + str(e.status_code))
    print("Error: " + str(e.error_message))

  return (
    gr.update(visible=True),  # show login page
    gr.update(visible=False), # hide main page
    "You have been logged out.",
    ["", ""]
  )

def logout_js():
  return """
  () => {
    window.history.replaceState({}, document.title, "/");
    setTimeout(() => { window.location.replace("/")}, 300);
  }
  """

# render webapp
def create_app():
  with gr.Blocks(title="Upload") as gradio_ui:
    stored_state = gr.BrowserState(["", "", ""])  # [session_token, refresh_token, user_email]

    login_page, email, send_button, login_message = create_login_page()
    main_page, logout_button = create_main_page(stored_state)

    send_button.click(
      fn=send_magic_link,
      inputs=[email],
      outputs=[login_message]
    )

    gradio_ui.load(
      fn=get_token_and_update_state,
      inputs=[stored_state],
      outputs=[login_page, main_page, login_message, stored_state]
    )

    logout_button.click(
      fn=logout_user,
      inputs=[stored_state],
      outputs=[login_page, main_page, login_message, stored_state],
      js=logout_js()
    )

  fastapi_app = gr.mount_gradio_app(app, gradio_ui, path="/", css=STYLE)
  return fastapi_app

# ============================================================================================================================================================================

# upload backend function
def upload(files, stored_state):
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state
  user_email = state_value[2] if len(state_value) > 2 else None

  if not user_email:
    return "Could not determine user identity. Please log in again.", []

  user_uuid = get_user_uuid(user_email)
  upload_uuid = str(uuid.uuid4())
  upload_dir = f"{BUCKET}/{user_uuid}/{upload_uuid}"

  # Build srcs list (same as before)
  srcs = []
  if isinstance(files, (str, bytes, os.PathLike)):
    srcs = [str(files)]
  elif isinstance(files, list):
    for f in files:
      if isinstance(f, str):
        srcs.append(f)
      elif isinstance(f, dict):
        p = f.get("tmp_path") or f.get("path") or f.get("name") or f.get("file")
        if p:
          srcs.append(p)
      elif hasattr(f, "name"):
        srcs.append(getattr(f, "name"))

  if not srcs:
    return "No valid local file paths found for upload.", []

  if RCLONE_CONFIG:
    rclone.set_config_file(RCLONE_CONFIG)

  # Check ALL existing files across all upload batches for this user
  existing = list_user_files(user_uuid)  # scans bucket/<user_uuid>/ recursively

  duplicates = []
  to_upload = []
  for s in srcs:
    name = os.path.basename(s)
    size = os.path.getsize(s)
    if name in existing and existing[name] == size:
      duplicates.append(name)
    else:
      to_upload.append(s)

  if not to_upload:
    dup_list = ", ".join(duplicates)
    return f"All files already exist in your storage: {dup_list}", []

  user_dir = f"{BUCKET}/{user_uuid}"
  is_new_user = not existing

  try:
    rclone.mkdir(upload_dir, args=["--verbose"])
  except Exception as e:
    print(f"mkdir warning: {e}")

  if is_new_user:
    write_user_meta(user_uuid, user_email)

  uploaded = []
  failures = []
  for s in to_upload:
    try:
      rclone.copy(s, upload_dir, ignore_existing=True, args=["--create-empty-src-dirs"])
      uploaded.append(s)
    except Exception as e:
      failures.append((s, str(e)))
      print(f"rclone.copy failed for {s}: {e}")

  if not uploaded:
    err = failures[0][1] if failures else "Unknown error"
    return f"Upload failed: {err}", []

  rows = [
    [os.path.basename(s), f"https://cdn.rundle.ab.ca/{user_uuid}/{upload_uuid}/{quote(os.path.basename(s))}"]
    for s in uploaded
  ]

  status_parts = [f"Uploaded {len(uploaded)} file(s) to path {user_uuid}/{upload_uuid}/"]
  if duplicates:
    status_parts.append(f"Skipped {len(duplicates)} duplicate(s): {', '.join(duplicates)}")
  if failures:
    status_parts.append(f"Failed: {', '.join(f[0] for f in failures)}")

  status = " | ".join(status_parts)

  try:
    send_upload_email(user_email, rows)
  except Exception as e:
    print(f"Email failed: {e}")

  return status, rows

def get_user_uuid(email):
  return str(uuid.uuid5(uuid.NAMESPACE_DNS, email.lower().strip()))

def list_user_files(user_uuid: str) -> dict[str, int]:
  """Returns {filename: size_in_bytes} across all upload batches for this user."""
  remote_path = f"{BUCKET}/{user_uuid}"
  try:
    result = subprocess.run(
      ["rclone", "--config", RCLONE_CONFIG, "lsjson", "--recursive", remote_path],
      capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
      return {}
    entries = json.loads(result.stdout or "[]")
    return {
      os.path.basename(e["Path"]): e["Size"]   # Path is relative: <upload_uuid>/<filename>
      for e in entries
      if not e.get("IsDir", False)
    }
  except Exception as e:
    print(f"lsjson failed: {e}")
    return {}

def extract_email_from_jwt(jwt_response):
  if not jwt_response:
    return ""
  claims = jwt_response.get("token") if isinstance(jwt_response.get("token"), dict) else jwt_response
  return (
    claims.get("email")
    or (claims.get("loginIds") or [""])[0]
    or claims.get("sub", "")
  ) or ""

def write_user_meta(user_uuid, email):
  import tempfile
  meta_path = os.path.join(tempfile.mkdtemp(), ".meta")
  with open(meta_path, "w") as f:
    f.write(email)
  try:
    rclone.copy(meta_path, f"{BUCKET}/{user_uuid}", args=["--verbose"])
    print(f"Written .meta for {user_uuid}")
  except Exception as e:
    print(f"Failed to write .meta: {e}")
  finally:
    os.remove(meta_path)

def send_upload_email(email, links):
  links_html = "".join(
    f'<tr><td style="border:1px solid #000000;padding:8px">{name}</td><td style="border:1px solid #000000;padding:8px">{url}</td></tr>'
    for name, url in links
  )
  email_html = f"""
  <table style="border-collapse:collapse;width:100%;background:#ffffff;color:#000000;border:2px solid #000000;font-family:sans-serif">
    <thead>
      <tr style="background:#ffffff">
        <th style="border:1px solid #000000;padding:8px;text-align:left">Filename</th>
        <th style="border:1px solid #000000;padding:8px;text-align:left">URL</th>
      </tr>
    </thead>
    <tbody>
      {links_html}
    </tbody>
  </table>
  """

  resend.api_key = RESEND_KEY
  resend.Emails.send({
    "from": "noreply@rundle.ab.ca",
    "to": email,
    "subject": "Your files were uploaded successfully to Rundle CDN",
    "html": email_html
  })

# ============================================================================================================================================================================

if __name__ == "__main__":
  import uvicorn
  run_app = create_app()
  uvicorn.run(run_app, host="127.0.0.1", port=7860)
