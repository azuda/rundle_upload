# backend.py

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

load_dotenv()
RCLONE_CONFIG = os.getenv("RCLONE_CONFIG")
BUCKET = os.getenv("BUCKET")
RESEND_KEY = os.getenv("RESEND_KEY")

# ============================================================================================================================================================================

def get_user_uuid(email: str) -> str:
  return str(uuid.uuid5(uuid.NAMESPACE_DNS, email.lower().strip()))

def extract_email_from_jwt(jwt_response) -> str:
  if not jwt_response:
    return ""
  claims = jwt_response.get("token") if isinstance(jwt_response.get("token"), dict) else jwt_response
  return (
    claims.get("email")
    or (claims.get("loginIds") or [""])[0]
    or claims.get("sub", "")
  ) or ""

def list_user_files(user_uuid: str) -> dict[str, int]:
  """returns { normalized_filename: size } across all uploads by this user"""
  remote_path = f"{BUCKET}/{user_uuid}"
  try:
    result = subprocess.run(
      ["rclone", "--config", RCLONE_CONFIG, "lsjson", "--recursive", remote_path],
      capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
      return {}
    entries = json.loads(result.stdout or "[]")
    # return {
    #   normalize_filename(os.path.basename(e["Path"])): e["Size"]
    #   for e in entries
    #   if not e.get("IsDir", False)
    # }
    return {
      normalize_filename(unquote(os.path.basename(e["Path"]))): e["Size"]
      for e in entries
      if not e.get("IsDir", False)
    }
  except Exception as e:
    print(f"lsjson failed: {e}")
    return {}

def write_user_meta(user_uuid: str, email: str):
  meta_name = "." + email.split("@")[0]
  meta_path = os.path.join(tempfile.mkdtemp(), meta_name)
  with open(meta_path, "w") as f:
    f.write(email)
  try:
    rclone.copy(meta_path, f"{BUCKET}/{user_uuid}", args=["--verbose"])
  except Exception as e:
    print(f"Failed to write .{meta_name}: {e}")
  finally:
    os.remove(meta_path)

def send_upload_email(email: str, links: list):
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

def normalize_filename(name: str) -> str:
  stem, ext = os.path.splitext(name)
  stem = re.sub(r'\s*-\s*copy(\s*\(?\d+\)?)?$', '', stem, flags=re.IGNORECASE)    # windows ex. " - Copy", " - Copy (1)", " - Copy 1"
  stem = re.sub(r'\s*\(\d+\)$', '', stem)                                         # " (1)", " (2)", etc.
  stem = re.sub(r'\s+copy(\s+\d+)?\s*$', '', stem, flags=re.IGNORECASE)           # macos ex. " copy", " copy 2"
  return stem.strip() + ext

def list_user_uploads(user_uuid: str) -> list[list[str]]:
  remote_path = f"{BUCKET}/{user_uuid}"
  try:
    result = subprocess.run(
      ["rclone", "--config", RCLONE_CONFIG, "lsjson", "--recursive", "--files-only", remote_path],
      capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
      return []
    entries = json.loads(result.stdout or "[]")
    rows = []
    for e in entries:
      path = e["Path"]             # e.g. "{upload_uuid}/filename.mp3"
      parts = path.split("/")
      if len(parts) < 2:
        continue
      filename = unquote(parts[-1])
      if filename.startswith("."):  # skip meta files
        continue
      upload_uuid = parts[0]
      url = f"https://cdn.rundle.ab.ca/{user_uuid}/{upload_uuid}/{quote(filename)}"
      rows.append([filename, url])
    return rows
  except Exception as e:
    print(f"list_user_uploads failed: {e}")
    return []

# ============================================================================================================================================================================

def upload(files, stored_state) -> tuple[str, list]:
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state
  user_email = state_value[2] if len(state_value) > 2 else None

  if not user_email:
    return "Could not determine user identity. Please log in again.", []

  user_uuid = get_user_uuid(user_email)
  upload_uuid = str(uuid.uuid4())
  upload_dir = f"{BUCKET}/{user_uuid}/{upload_uuid}"

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

  # check all existing files in all subdirs for this user
  existing = list_user_files(user_uuid)

  duplicates = []
  to_upload = []
  for s in srcs:
    name = os.path.basename(s)
    normalized = normalize_filename(name)
    size = os.path.getsize(s)
    if normalized in existing and existing[normalized] == size:
      duplicates.append(normalized)
    else:
      to_upload.append(s)

  if not to_upload:
    dup_list = "\n".join(duplicates)
    return f"All files have already been uploaded:\n{dup_list}\n\nPlease check your email inbox for previous upload results.", []

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

  status_parts = [f"Uploaded {len(uploaded)} file(s) to path {user_uuid}/{upload_uuid}/:\n" + "\n".join(os.path.basename(s) for s in uploaded)]
  if duplicates:
    status_parts.append(f"Skipped {len(duplicates)} duplicate(s):\n{chr(10).join(duplicates)}\n\nPlease check your email inbox for previous upload results.")
  if failures:
    status_parts.append(f"Failed: {', '.join(f[0] for f in failures)}")

  status = "\n\n".join(status_parts)

  try:
    send_upload_email(user_email, rows)
  except Exception as e:
    print(f"Email failed: {e}")

  return status, rows

def unupload(link: str, stored_state) -> tuple[str, list]:
  state_value = stored_state.value if hasattr(stored_state, 'value') else stored_state
  user_email = state_value[2] if len(state_value) > 2 else None
  if not user_email:
    return "Could not determine user identity, please log in again."
  
  # check user_uuid
  user_uuid = get_user_uuid(user_email)
  if user_uuid not in link:
    return "Delete failed: you do not have permission to delete this file."

  link_path = unquote(link).replace("https://cdn.rundle.ab.ca/", "r2:canvas-storage/")

  # check file exists
  check = subprocess.run(
    ["rclone", "--config", RCLONE_CONFIG, "lsjson", link_path],
    capture_output=True, text=True, timeout=30
  )
  entries = json.loads(check.stdout or "[]")
  if not entries:
    return "Delete failed: file not found."

  # delete file
  result = subprocess.run(
    ["rclone", "--config", RCLONE_CONFIG, "deletefile", link_path, "--verbose"],
    capture_output=True, text=True, timeout=30
  )
  if result.returncode != 0:
    return f"rclone deletefile failed: {result.stderr.strip() or 'unknown error'}"

  return f"Successfully deleted file at {link}"
