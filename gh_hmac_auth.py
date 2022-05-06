
import hashlib
import hmac
import base64
import time
import random
import string
from requests.auth import AuthBase
from typing import Optional


class GhHmacAuth(AuthBase):
    SIGNATURE_DELIM = "\n"
    HOST = "api-third-party-gtm-pp.grubhub.com"  # Ideally an env var
    PORT = 443  # HTTPS generally runs on port 443 
    HTTP_HEADER = "AUTHORIZATION"
    PARTNER_KEY_HEADER = "X-GH-PARTNER-KEY"

    def __init__(self, client_id, client_secret, issue_date, partner_key):
        self.client_id = client_id
        self.client_secret = client_secret
        self.issue_date = issue_date
        self.partner_key = partner_key

    def __call__(self, request, request_method, request_uri, body: Optional[str] = "", ext: Optional[str] = ""):
        self._encode(request=request, method=request_method, uri=request_uri, body=body, ext=ext)
        return request

    def _encode(self, request, body: str, method: str, uri: str, ext: Optional[str]):
        nonce = self._generate_nonce()
        body_hash = self._hash_body(body)
        normal_request = self._normalize_request(nonce, method, uri, GhHmacAuth.HOST, GhHmacAuth.PORT, body_hash, ext)
        signature = self._sign(normal_request)
        header_value = self._format(nonce, body_hash, ext, signature)
        request[GhHmacAuth.HTTP_HEADER] = header_value
        request[GhHmacAuth.PARTNER_KEY_HEADER] = self.partner_key
        return

    def _generate_nonce(self):
        timestamp = time.time()
        otp = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        nonce = f"{round(self.issue_date - timestamp)}:{otp}"
        return nonce

    def _hash_body(self, body):
        if body:
            return base64.b64encode(hashlib.sha256(bytes(body, encoding="utf-8")).digest()).decode('utf-8')
        return ""

    def _normalize_request(self, nonce: str, request_method: str,
                           request_uri: str, host: str,
                           port: int, body_hash: str, ext: str) -> str:
        return (f"{nonce}{GhHmacAuth.SIGNATURE_DELIM}"
                f"{request_method.upper()}{GhHmacAuth.SIGNATURE_DELIM}"
                f"{request_uri}{GhHmacAuth.SIGNATURE_DELIM}"
                f"{host.lower()}{GhHmacAuth.SIGNATURE_DELIM}"
                f"{str(port)}{GhHmacAuth.SIGNATURE_DELIM}"
                f"{body_hash}{GhHmacAuth.SIGNATURE_DELIM}"
                f"{ext}{GhHmacAuth.SIGNATURE_DELIM}")

    def _sign(self, content):
        requestBytes = bytes(content, encoding="utf-8")
        secretBytes = bytes(self.client_secret, encoding="utf-8")
        signature = base64.b64encode(hmac.new(secretBytes, requestBytes, digestmod=hashlib.sha256).digest()).decode('utf-8')
        return signature

    def _format(self, nonce: str, body_hash: str, ext: str, mac: str) -> str:
        header_value = ""
        header_value += f"MAC id=\"{self.client_id}\",nonce=\"{nonce}"
        if body_hash:
            header_value += f"\",bodyhash=\"{body_hash}"
        if ext:
            header_value += f"\",ext=\"{ext}"
        header_value += f"\",mac=\"{mac}\""
        return header_value
