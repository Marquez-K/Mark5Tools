import base64
import hashlib
import hmac
import json

HASH_TYPE = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512
}

header = {
    "alg":"HS512"
}

payload = {
    "admin":"admin"
}

hmac_secret = "abcdefgh"

def hash_detect(alg):
    if alg not in HASH_TYPE:
        raise ValueError(f"Unsupported algorithm: {alg}")
    return HASH_TYPE[alg]

def create_jwt(header, payload, secret):
    key = base64.urlsafe_b64decode(secret)

    # Convert header and payload to JSON and then to base64url
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload, separators=(',', ':'))

    header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')

    msg = f"{header_b64}.{payload_b64}".encode()

    # Create HMAC signature
    jwt_encode = hmac.new(
        key=key,
        msg=msg,
        digestmod=hash_detect(header["alg"])
    ).digest()

    jwt_encode_b64 = base64.urlsafe_b64encode(jwt_encode).decode().rstrip('=')

    return f"{header_b64}.{payload_b64}.{jwt_encode_b64}"


jwt_token = create_jwt(header, payload, hmac_secret)
print(jwt_token)