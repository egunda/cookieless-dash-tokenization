# main.py
import os
import re
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse, urljoin, urlsplit, parse_qs

import functions_framework
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import Response

# --- Configuration ---

# --- MODIFIED ---
# The PEM-formatted private key is now hardcoded here.
SECRET_PRIVATE_KEY_PEM = """
-----BEGIN PRIVATE KEY-----
your key here
-----END PRIVATE KEY-----
"""

GCS_ORIGIN_HOST = os.environ.get('GCS_ORIGIN_HOST', 'storage.googleapis.com/mybuckey')
MEDIA_CDN_HOST = os.environ.get('MEDIA_CDN_HOST', 'cdnhostname.com')
SIGNING_KEY_NAME = os.environ.get('SIGNING_KEY_NAME', 'signedkey')
TOKEN_LIFETIME_SECONDS = int(os.environ.get('TOKEN_LIFETIME_SECONDS', 86400))

# --- ED25519 Signing Logic (MODIFIED to use PEM string) ---
def sign_url_ed25519(url: str, key_name: str) -> str:
    """Signs a URL using the global ED25519 PEM private key."""
    try:
        # Load the private key directly from the PEM string.
        private_key = serialization.load_pem_private_key(
            SECRET_PRIVATE_KEY_PEM.encode('utf-8'),
            password=None
        )
    except Exception as e:
        print(f"FATAL: Could not load ED25519 PEM private key. Error: {e}")
        raise

    expiration_time = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_LIFETIME_SECONDS)
    expiration_timestamp = int(expiration_time.timestamp())
    
    parsed_url = urlsplit(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    
    separator = '&' if query_params else '?'
    url_to_sign = f"{url}{separator}Expires={expiration_timestamp}&KeyName={key_name}"

    signature_bytes = private_key.sign(url_to_sign.encode("utf-8"))
    encoded_signature = base64.urlsafe_b64encode(signature_bytes).decode("utf-8")
    
    signed_url = f"{url_to_sign}&Signature={encoded_signature}"
    return signed_url

# --- Regex for manifest parsing (No changes) ---
URL_REGEX = re.compile(
    r'(<BaseURL>([^<]+)</BaseURL>)|'
    r'((?:href|src|media|initialization)\s*=\s*["\']([^"\']+)["\'])',
    re.IGNORECASE
)
PATH_TO_TOKENIZE_REGEX = re.compile(r'(\.mpd|\.m3u8|\.m4s|\.ts|\.mp4)', re.IGNORECASE)

def tokenize_manifest(manifest_content: str, base_path: str) -> str:
    """Scans and replaces URLs with their tokenized versions."""
    def replacer(match):
        is_tag_match = match.group(1) is not None
        original_url = match.group(2) if is_tag_match else match.group(4)
        original_full_match = match.group(0)

        if not PATH_TO_TOKENIZE_REGEX.search(original_url):
            return original_full_match

        parsed_original = urlparse(original_url)
        if parsed_original.scheme or parsed_original.netloc or original_url.startswith('/'):
            path_for_signing = parsed_original.path
        else:
            path_for_signing = urljoin(base_path + '/', original_url)
        
        full_url_to_sign = f"https://{MEDIA_CDN_HOST}{path_for_signing}"
        
        # --- MODIFIED --- 
        # The key is no longer passed as an argument.
        signed_url_with_params = sign_url_ed25519(full_url_to_sign, SIGNING_KEY_NAME)
        
        token_query = urlparse(signed_url_with_params).query
        
        new_query = f"{parsed_original.query}&{token_query}" if parsed_original.query else token_query
        tokenized_url = urlunparse(list(parsed_original)[:4] + [new_query] + list(parsed_original)[5:])

        if is_tag_match:
            return f"<BaseURL>{tokenized_url}</BaseURL>"
        else:
            return original_full_match.replace(original_url, tokenized_url)

    return URL_REGEX.sub(replacer, manifest_content)

@functions_framework.http
def manifest_tokenizer(request):
    """The main handler for the Cloud Function."""
    # --- MODIFIED ---
    # Removed the check for the private key env var.
    if not all([GCS_ORIGIN_HOST, SIGNING_KEY_NAME, MEDIA_CDN_HOST]):
        print("Error: A required environment variable is not set.")
        return Response("Internal configuration error.", status=500)

    request_path = request.path
    if not request_path or request_path == '/':
        return Response("Please specify a manifest path in the URL.", status=400)

    base_path = os.path.dirname(request_path)
    gcs_download_url = f"https://{GCS_ORIGIN_HOST}{request_path}"

    try:
        response = requests.get(gcs_download_url)
        response.raise_for_status()
        manifest_content = response.text

        tokenized_manifest = tokenize_manifest(manifest_content, base_path)

        return Response(
            tokenized_manifest,
            mimetype=response.headers.get('Content-Type', 'application/dash+xml'),
            status=response.status_code,
            headers={'Cache-Control': 'no-cache, no-store, must-revalidate'}
        )
    except Exception as e:
        print(f"Error during execution: {e}")
        return Response(f"Internal server error: {e}", mimetype="text/plain", status=500)
