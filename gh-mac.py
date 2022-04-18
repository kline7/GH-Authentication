import hashlib
import hmac
import base64
import time
import random, string
import datetime
import json

NEW_LINE = "\n"

# Init?
client_id = "sv:v1:c78ada21-62fa-11e5-ba00-43d58aece945"
secret = "qwfXhRvs6r5xJEEK37KO+qvSGvAijtJ/vG8xim6e+xo="
issue_date = 1443126493378

body = json.dumps({"task_id":"ae463g"})
request_method = "GET"
host = "pos-api-url.grubhub.com"
port = 443
uri = "/pos/v1/merchant/11446280/orders"
ext = ""

# Generate Nonce Method
def _generate_nonce() -> str:
    t = time.time()
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    new_nonce = f"{round(issue_date - t)}:{token}"
    return new_nonce
  
# Hash body Method
def _hash_body(body: str) -> str:
    if not body:
        return ""
    return base64.b64encode(hashlib.sha256(bytes(body, encoding="utf-8")).digest())

# Normalize request Method
def _normalize_request(nonce: str, request_method: str, request_uri: str, host: str, port: int, body_hash: str, ext: str) -> str:
	return (f"{nonce}{NEW_LINE}"
          f"{request_method.upper()}{NEW_LINE}"
          f"{request_uri}{NEW_LINE}"
          f"{host.lower()}{NEW_LINE}"
          f"{str(port)}{NEW_LINE}"
          f"{body_hash}{NEW_LINE}"
          f"{ext}{NEW_LINE}")

# Hash normalized request Method
def _hash_normalized_request(request, secret) -> str:
    requestBytes = bytes(request, encoding='utf-8')
    secretBytes = bytes(secret, encoding='utf-8')
    signature = base64.b64encode(hmac.new(secretBytes, requestBytes, digestmod=hashlib.sha256).digest())
    return signature

# Create header value Method
def _create_header_value(client_id: str, nonce: str, body_hash: str, ext: str, mac: str) -> str:
    header_value = ""
    header_value += f"MAC id=\"{client_id}\",nonce=\"{nonce}"

    if body_hash:
        header_value += f"\",bodyhash=\"{body_hash}"

    if ext:
        header_value += f"\",ext=\"{ext}"

    header_value += f"\",mac=\"{mac}\""
    return header_value

def create_authentication_header(body: str, method: str, uri: str) -> str:
  auth_nonce = _generate_nonce()
  body_hash = _hash_body(body).decode('utf-8')
  normal_request = _normalize_request(auth_nonce, method, 
                                       uri, host, port, body_hash, ext)
  hashed_normal_request = _hash_normalized_request(normal_request, secret).decode('utf-8')
  header_value = _create_header_value(client_id, auth_nonce, body_hash, ext, hashed_normal_request)
  return header_value

# Generate the value that should actually be used in the "Authorization" HTTP header
header_value = create_authentication_header(body, request_method, uri)
print(f"header_value: {header_value}")
