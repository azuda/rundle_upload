# app.py

# sso w magic link source
# https://github.com/benitomartin/gradio-sso-auth-descope

import gradio as gr
from flask import Flask, request, redirect
from descope import DescopeClient, DeliveryMethod, AuthException
import os
from dotenv import load_dotenv
from threading import Thread
from rclone_python import rclone
import uuid
import shutil

# descope client setup
load_dotenv()
PROJECT_ID = os.getenv("DESCOPE_ID")
descope_client = DescopeClient(project_id=PROJECT_ID)

# config for cloudflare r2 storage upload
RCLONE_CONFIG = os.getenv("RCLONE_CONFIG")
BUCKET = os.getenv("BUCKET")

# change accepted file formats here
FILE_TYPES = [".mp3", ".wav", ".m4a", ".pdf"]

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

PORT = os.getenv("PORT")

# ===============================================================================================================================

# flask setup

app = Flask(__name__)

@app.route('/verify')
def verify_magic_link():
  token = request.args.get('t')
  if token == None:
    token = request.args.get('token')

  if not token:
    return "Error: Token is missing from the URL", 400

  try:
    # verify token w descope
    user_response = descope_client.magiclink.verify(token)
    print(f"User response: {user_response}")

    # extract session and refresh tokens from descope response
    session_token = user_response.get('sessionToken')
    refresh_token = user_response.get('refreshToken')

    if isinstance(session_token, dict):
      session_token = session_token.get('jwt')
    if isinstance(refresh_token, dict):
      refresh_token = refresh_token.get('jwt')

    print(f"Session token type: {type(session_token)}")
    print(f"Session token value: {session_token}")
    print(f"Refresh token type: {type(refresh_token)}")

    if not session_token:
      raise AuthException("Failed to retrieve session token.")
    if not refresh_token:
      raise AuthException("Failed to retrieve refresh token.")

    # redirect to gradio app w session and refresh tokens in url
    # redirect_url = f'http://127.0.0.1:7860/?token={session_token}'
    redirect_url = f"https://upload.rundle.ab.ca/?t={session_token}&r={refresh_token}"
    print(f"Redirecting to: {redirect_url}")
    return redirect(redirect_url)

  except AuthException as e:
    error_message = str(e)
    # Check if this is a token expiration error
    if "expired" in error_message.lower() or "invalid" in error_message.lower():
      return "This magic link has expired. Please request a new one.", 401
    return f"Authentication error: {error_message}", 400
  except Exception as e:
    return f"Error verifying magic link: {str(e)}", 500

@app.after_request
def disable_cache(response):
  response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
  response.headers['Pragma'] = 'no-cache'
  response.headers['Expires'] = '-1'
  return response

# ===============================================================================================================================

# frontend + handle descope magic link sso

def send_magic_link(email):
  if not email.endswith("@rundle.ab.ca"):
    return "Error: Please use your Rundle email address."

  try:
    # generate magic link
    descope_client.magiclink.sign_up_or_in(
      method=DeliveryMethod.EMAIL,
      login_id=email,
      # uri=f"http://127.0.0.1:5000/verify"  # redirect uri for flask
      uri=f"https://upload.rundle.ab.ca"
    )
    return f"Magic link sent to {email}! Please check your inbox."
  except Exception as e:
    return f"Error sending magic link: {str(e)}"

def get_token_and_update_state(stored_state, request: gr.Request):
  try:
    # get current request context
    query_params = dict(request.query_params)
    print(f"Query params: {query_params}")

    if query_params:
      token = query_params.get('t')
      if token == None:
        token = query_params.get('token')

      if token:
        print(f"Token received: {token}")
        refresh_token = query_params.get('r', '')

        # return tokens to be stored in browserstate
        # Note: token validation happens in load_stored_session on subsequent page loads
        return (
          gr.update(visible=False), # hide login page
          gr.update(visible=True),  # show main page
          f"Successfully logged in!",
          [token, refresh_token] # store session and refresh tokens
        )

  except Exception as e:
    print(f"Error processing request: {e}", exc_info=True)

  # default return if no token or error
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
def create_main_page():
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
    output_table = gr.Dataframe(headers=["File Name", "URL"], label="Uploaded Files", datatype=["str", "str"])
    upload_button.click(upload, inputs=[files_input], outputs=[status_output, output_table])
    logout_button = gr.Button("Logout", variant="secondary")
  return main_page, logout_button

def load_stored_session(stored_state):
  # extract value from browserstate obj
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state
  print(f"Loading session, state_value: {state_value}, type: {type(state_value)}")

  # check if valid tokens exist
  session_token = None
  refresh_token = None

  if isinstance(state_value, list) and len(state_value) > 0:
    session_token = state_value[0] if state_value[0] else None
    refresh_token = state_value[1] if len(state_value) > 1 else None

  print(f"Has session token: {bool(session_token)}, Has refresh token: {bool(refresh_token)}")

  # ---
  if session_token:
    try:
      jwt_response = descope_client.validate_session(session_token)
      print(f"Session validated successfully")

      return (
        gr.update(visible=False),
        gr.update(visible=True),
        f"Welcome back!",
        [session_token, refresh_token]  # keep original tokens
      )
    except Exception as e:
      print(f"Session expired or invalid: {str(e)}")
      
      # Try to refresh the session using refresh token
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
            return (
              gr.update(visible=False),
              gr.update(visible=True),
              f"Session refreshed. Welcome back!",
              [new_session_token, new_refresh_token]
            )
        except Exception as refresh_error:
          print(f"Failed to refresh session: {str(refresh_error)}")

  # Show login page if no valid session
  return (
    gr.update(visible=True),
    gr.update(visible=False),
    "Your session has expired. Please log in again.",
    ["", ""]
  )

def logout_user(stored_state):
  # clear session and reset ui to login page
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state

  # kill token on descope side
  try:
    if isinstance(state_value, list) and len(state_value) > 0 and state_value[0]:
      # check if token is a jwt str or a dict
      token_str = state_value[0]
      if isinstance(token_str, str):
        # try to kill on descope
        descope_client.logout_all(token_str)
        print(f"Token invalidated on Descope")
  except AuthException as e:
    # print(f"Error invalidating token: {str(e)}")
    print ("Failed to log user out of all current sessions.")
    print ("Status Code: " + str(e.status_code))
    print ("Error: " + str(e.error_message))

  # return empty token list and show login page
  return (
    gr.update(visible=True),  # show login page
    gr.update(visible=False), # hide main page
    "You have been logged out.",
    ["", ""]  # clear both tokens
  )

def logout_js():
  return """
  () => {
    // Clear history so 'back' button doesn't work
    window.history.replaceState({}, document.title, "/");
    // Use location.replace to ensure the current entry is overwritten
    setTimeout(() => { window.location.replace("/")}, 300);
  }
  """

# render webapp
def create_app():
  with gr.Blocks(title="Upload") as app:
    stored_state = gr.BrowserState(["", ""])  # [session_token, refresh_token]

    login_page, email, send_button, login_message = create_login_page()
    main_page, logout_button = create_main_page()

    send_button.click(
      fn=send_magic_link,
      inputs=[email],
      outputs=[login_message]
    )

    app.load(
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

  return app

def run_gradio():
  gradio_app = create_app()
  gradio_app.launch(css=STYLE)

# ============================================================================================================================================================================

# uploader backend

def upload(files):
  global RCLONE_CONFIG, BUCKET
  # normalize possible gradio.file inputs to list of local paths
  srcs = []
  if isinstance(files, (str, bytes, os.PathLike)):
    srcs = [str(files)]
  elif isinstance(files, list):
    for f in files:
      if isinstance(f, str):
        srcs.append(f)
      elif isinstance(f, dict):
        # dict with tmp_path / name / file / path
        p = f.get("tmp_path") or f.get("path") or f.get("name") or f.get("file")
        if p:
          srcs.append(p)
      elif hasattr(f, "name"):
        srcs.append(getattr(f, "name"))
  else:
    print(f"Unhandled files input type: {type(files)} -> {files}")

  if not srcs:
    return "No valid local file paths found for upload", []

  if RCLONE_CONFIG:
    rclone.set_config_file(RCLONE_CONFIG)
  else:
    print("RCLONE_CONFIG not set")

  id_path = str(uuid.uuid4())
  remote_path = f"{BUCKET}/DIGIEXAM/{id_path}"
  try:
    rclone.mkdir(remote_path, args=["--verbose"])
    print("============================================================================================")
    print(f"Created directory {remote_path} in R2")
    print("============================================================================================")
  except Exception as e:
    print(f"rclone.mkdir warning: {e}")

  # copy each source individually to avoid rclone_python converting a list into a single string
  uploaded = []
  failures = []
  for s in srcs:
    try:
      rclone.copy(s, remote_path, ignore_existing=True, args=["--create-empty-src-dirs"])
      uploaded.append(s)
    except Exception as e:
      failures.append((s, str(e)))
      print(f"rclone.copy failed for {s}: {e}")

  if not uploaded:
    # return first failure message if available
    err = failures[0][1] if failures else "Unknown error"
    return f"Upload failed: {err}", []

  status_message = f"Uploaded {len(uploaded)} file(s) to Rundle CDN with path {remote_path}"
  print(status_message)

  # rows for output table [filename, url]
  rows = [[os.path.basename(s), f"https://cdn.rundle.ab.ca/DIGIEXAM/{id_path}/{os.path.basename(s)}"] for s in uploaded]
  return status_message, rows

def process_fileobj(fileobj):
  result = []
  path = f"{os.getcwd()}/{os.path.basename(fileobj)}"
  shutil.copyfile(fileobj.name, path)
  result.append(path)
  return result

def test():
  global RCLONE_CONFIG, BUCKET
  rclone.set_config_file(RCLONE_CONFIG)
  testdir = f"{BUCKET}/DIGIEXAM/test_upload"
  rclone.mkdir(testdir)
  rclone.copy("/Users/azhang/Downloads/tmp7b0w9dvs.mp3", testdir, ignore_existing=True, args=["--create-empty-src-dirs"])
  print("=================== test upload done")

# ============================================================================================================================================================================

if __name__ == "__main__":
  # start flask in separate thread to handle /verify endpoint
  def run_flask():
    # app.run(host="127.0.0.1", port=PORT, use_reloader=False)
    app.run(host="upload.rundle.ab.ca", port=PORT, use_reloader=False)

  flask_thread = Thread(target=run_flask)
  flask_thread.start()

  # start gradio app in main thread
  run_gradio()
