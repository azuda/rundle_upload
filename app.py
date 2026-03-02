# app.py

# sso w magic link via descope
# https://github.com/benitomartin/gradio-sso-auth-descope

from descope import DescopeClient, AuthException
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, PlainTextResponse
import gradio as gr
import os
from starlette.requests import Request

from frontend import create_gradio_ui, STYLE

load_dotenv()
PROJECT_ID = os.getenv("DESCOPE_ID")
descope_client = DescopeClient(project_id=PROJECT_ID)

# ============================================================================================================================================================================

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

# ============================================================================================================================================================================

def create_app():
  gradio_ui = create_gradio_ui()
  fastapi_app = gr.mount_gradio_app(app, gradio_ui, path="/", css=STYLE)
  return fastapi_app

if __name__ == "__main__":
  import uvicorn
  run_app = create_app()
  uvicorn.run(run_app, host="127.0.0.1", port=7860)
