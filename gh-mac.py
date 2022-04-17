import hashlib
import hmac
import base64

NEW_LINE = "\n"

client_id = "sv:v1:c78ada21-62fa-11e5-ba00-43d58aece945"
secret = "qwfXhRvs6r5xJEEK37KO+qvSGvAijtJ/vG8xim6e+xo="
issue_date = 1443126493378

nonce = "7349622:vCZfJEjW"
body = '{"task_id":"ae463g"}'
request_method = "GET"
host = "pos-api-url.grubhub.com"
port = 443
uri = "/pos/v1/merchant/11446280/orders"
ext = ""

def generate_nonce():
    return nonce
  
def hash_body(body):
    if not body:
        return ""

    return base64.b64encode(hashlib.sha256(bytes(body, encoding="utf-8")).digest())

def normalize_request(nonce: str, request_method: str, request_uri: str, host: str, port: int, body_hash, ext: str) -> str:
	return f"{nonce}{NEW_LINE}{request_method.upper()}{NEW_LINE}{request_uri}{NEW_LINE}{host.lower()}{NEW_LINE}{str(port)}{NEW_LINE}{body_hash}{NEW_LINE}{ext}{NEW_LINE}"

def hash_normalized_request(request, secret):
    requestBytes = bytes(request, encoding='utf-8')
    secretBytes = bytes(secret, encoding='utf-8')
    signature = base64.b64encode(hmac.new(secretBytes, requestBytes, digestmod=hashlib.sha256).digest())
    return signature

def create_header_value(client_id, nonce, body_hash, ext, mac):
    header_value = ""
    header_value += f"MAC id=\"{client_id}\",nonce=\"{nonce}"

    if body_hash:
        header_value += f"\",bodyhash=\"{body_hash.decode('utf-8')}"

    if ext:
        header_value += f"\",ext=\"{ext}"

    header_value += f"\",mac=\"{mac.decode('utf-8')}\""
    return header_value

# Generate a one time use nonce (hard-coded here, but should be something like seconds between issue date and system date, colon, a random alphanumeric string)
generated_nonce = generate_nonce()
print(f"nonce: {generated_nonce}")
# SHA256 hash the body and base64 encode the result
body_hash = hash_body(body)
print(f"body_hash: {body_hash}")
# Normalize the pieces of the request to ensure the hash, in the next step, matches what the service expects
normalized_request = normalize_request(nonce, request_method, uri, host, port, body_hash, ext)
print(f"normalized_request: {repr(normalized_request)}")
# HMAC SHA256 hash the normalized request using the client secret and base64 encode the result
hashed_normalized_request = hash_normalized_request(normalized_request, secret)
print(f"hashed_normalized_request: {hashed_normalized_request.decode('utf-8')}")
# Generate the value that should actually be used in the "Authorization" HTTP header
header_value = create_header_value(client_id, nonce, body_hash, ext, hashed_normalized_request)
print(f"header_value: {header_value}")
