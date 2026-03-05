# frontend.py

from descope import DescopeClient, DeliveryMethod, AuthException
from dotenv import load_dotenv
import gradio as gr
import pandas as pd
import os

from backend import extract_email_from_jwt, get_user_uuid, list_user_uploads, upload, unupload

load_dotenv()
PROJECT_ID = os.getenv("DESCOPE_ID")
descope_client = DescopeClient(project_id=PROJECT_ID)

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

# ============================================================================================================================================================================

def send_magic_link(email: str) -> str:
  if not email.endswith("@rundle.ab.ca"):
    return "Error: Please use your Rundle email address."
  try:
    descope_client.magiclink.sign_up_or_in(
      method=DeliveryMethod.EMAIL,
      login_id=email,
      uri="https://upload.rundle.ab.ca/verify"
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
          gr.update(visible=False),  # hide login page
          gr.update(visible=True),   # show main page
          "Successfully logged in!",
          [token, refresh_token, user_email]
        )
  except Exception as e:
    print(f"Error processing request: {e}", exc_info=True)

  print("No token in URL, checking stored state...")
  return load_stored_session(stored_state)

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
      print("Session validated successfully")
      return (
        gr.update(visible=False),
        gr.update(visible=True),
        "Welcome back!",
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
              "Session refreshed. Welcome back!",
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
        print("Token invalidated on Descope")
  except AuthException as e:
    print("Failed to log user out of all current sessions.")
    print("Status Code: " + str(e.status_code))
    print("Error: " + str(e.error_message))

  return (
    gr.update(visible=True),   # show login page
    gr.update(visible=False),  # hide main page
    "You have been logged out.",
    ["", ""]
  )

def logout_js():
  return """
  () => {
    window.history.replaceState({}, document.title, "/");
    setTimeout(() => { window.location.replace("/") }, 300);
  }
  """

# ============================================================================================================================================================================

def create_login_page():
  with gr.Row(visible=True) as login_page:
    with gr.Column(scale=3):
      email = gr.Textbox(label="Enter your email to log in:")
      send_button = gr.Button("Send One-Time Verification Link", elem_id="button_colour")
    with gr.Column(scale=2):
      login_message = gr.Textbox(label="Status", interactive=False, lines=2, max_lines=16)
    email.submit(fn=send_magic_link, inputs=[email], outputs=[login_message])
  return login_page, email, send_button, login_message

def create_main_page(stored_state):
  with gr.Column(visible=False) as main_page:
    with gr.Row():
      with gr.Column(scale=11):
        gr.Markdown("# Rundle CDN Uploader")
        gr.Markdown("Turn your files into easily shareable links by uploading them to the Rundle Cloudflare R2 Storage Bucket.")
      with gr.Column(scale=1):
        admin_button = gr.Button("Admin", variant="huggingface")
    with gr.Row():
      with gr.Column(scale=3):
        files_input = gr.Files(label="Select file(s) to upload...", file_types=FILE_TYPES)
        upload_button = gr.Button("Upload File(s)", elem_id="button_colour")
      with gr.Column(scale=2):
        link_to_delete = gr.Textbox(label="Enter URL of a file to delete from cloud storage (exact match required):", lines=1, max_lines=2)
        delete_button = gr.Button("Delete File", variant="huggingface")
    with gr.Column():
      status_output = gr.Textbox(label="Status", interactive=False, lines=4, max_lines=16)
      output_table = gr.Dataframe(
        headers=["Filename", "URL", "Date Modified"],
        label="Your Uploaded Files",
        datatype=["str", "str", "str"],
        column_widths=["20%", "60%", "20%"]
      )
      logout_button = gr.Button("Logout", variant="secondary")

    upload_button.click(
      fn=do_upload,
      inputs=[files_input, stored_state],
      outputs=[status_output, output_table]
    )
    delete_button.click(
      fn=unupload,
      inputs=[link_to_delete, stored_state],
      outputs=[status_output]
    ).then(
      fn=lambda: gr.update(value=""),
      inputs=[],
      outputs=[link_to_delete]
    ).then(
      fn=build_table,
      inputs=[stored_state],
      outputs=[output_table]
    )
    link_to_delete.submit(
      fn=unupload,
      inputs=[link_to_delete, stored_state],
      outputs=[status_output]
    ).then(
      fn=lambda: gr.update(value=""),
      inputs=[],
      outputs=[link_to_delete]
    ).then(
      fn=build_table,
      inputs=[stored_state],
      outputs=[output_table]
    )
  return main_page, output_table, logout_button

def create_gradio_ui() -> gr.Blocks:
  # with gr.Blocks(title="Uploader", css=STYLE) as gradio_ui:
  with gr.Blocks(title="Uploader") as gradio_ui:
    stored_state = gr.BrowserState(["", "", "", True])

    login_page, email, send_button, login_message = create_login_page()
    main_page, output_table, logout_button = create_main_page(stored_state)  # <-- unpack output_table

    send_button.click(fn=send_magic_link, inputs=[email], outputs=[login_message])

    gradio_ui.load(
      fn=get_token_and_update_state,
      inputs=[stored_state],
      outputs=[login_page, main_page, login_message, stored_state]
    ).then(
      fn=build_table,          # populate table after login state is resolved
      inputs=[stored_state],
      outputs=[output_table]
    )

    logout_button.click(
      fn=logout_user,
      inputs=[stored_state],
      outputs=[login_page, main_page, login_message, stored_state],
      js=logout_js()
    )

  return gradio_ui

def build_table(stored_state, highlight_urls: set = None):
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state
  user_email = state_value[2] if isinstance(state_value, list) and len(state_value) > 2 else ""
  
  all_rows = []
  if user_email:
    user_uuid = get_user_uuid(user_email)
    all_rows = list_user_uploads(user_uuid)

  # move highlighted rows to top
  n_highlighted = 0
  if highlight_urls:
    highlighted = [r for r in all_rows if r[1] in highlight_urls]
    rest        = [r for r in all_rows if r[1] not in highlight_urls]
    all_rows = highlighted + rest
    n_highlighted = len(highlighted)

  df = pd.DataFrame(all_rows if all_rows else [], columns=["Filename", "URL", "Date Modified"])
  df = df.sort_values("Date Modified", ascending=False).reset_index(drop=True)

  if n_highlighted > 0:
    highlight_indices = set(range(n_highlighted))
    def _style_rows(row):
      return ["background-color: #515115"] * len(row) if row.name in highlight_indices else [""] * len(row)
    return df.style.apply(_style_rows, axis=1)

  return df.style

def do_upload(files, stored_state):
  """wrapper function to run upload() + rebuild output_table"""
  status, new_rows = upload(files, stored_state)
  highlight_urls = {r[1] for r in new_rows} if new_rows else set()
  return status, build_table(stored_state, highlight_urls)
