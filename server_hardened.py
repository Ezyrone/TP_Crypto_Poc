import json
import time
import hmac
import hashlib
import base64
import os
import uuid
import secrets

from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__, static_folder="frontend", static_url_path="")
PORT = 3001

TOKEN_TTL_SECONDS = 15 * 60
HS256_SECRET_STRONG = os.environ.get("JWT_SECRET", secrets.token_hex(32))

print(f"[DURCI] Secret HS256 : {HS256_SECRET_STRONG}")

KEY_STORE = {
    "key-v1": secrets.token_hex(32),
    "key-v2": HS256_SECRET_STRONG,
}
CURRENT_KID = "key-v2"

RSA_PUBLIC_KEY = None
RSA_PUBLIC_PEM = None
keys_dir = os.path.join(os.path.dirname(__file__), "keys")
try:
    with open(os.path.join(keys_dir, "public.pem"), "rb") as f:
        RSA_PUBLIC_PEM = f.read()
        RSA_PUBLIC_KEY = serialization.load_pem_public_key(RSA_PUBLIC_PEM)
except FileNotFoundError:
    print("[WARN] Cles RSA manquantes — /api/secret-rs256 desactive.")

TOKEN_BLACKLIST = set()

USERS = {
    "alice": {"password": "password123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode_json(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def b64url_decode_json(s):
    return json.loads(b64url_decode(s))


def sign_hs256_hardened(payload):
    now = int(time.time())
    header = b64url_encode_json({"alg": "HS256", "typ": "JWT", "kid": CURRENT_KID})
    body = b64url_encode_json({
        **payload,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    })
    secret = KEY_STORE[CURRENT_KID]
    sig = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64url_encode(sig)}"


def verify_hs256_hardened(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Format invalide")

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])
    sig = parts[2]

    if header.get("alg") != "HS256":
        raise ValueError(f'Algorithme refuse : "{header.get("alg")}" (seul HS256 est autorise)')

    kid = header.get("kid", CURRENT_KID)
    secret = KEY_STORE.get(kid)
    if not secret:
        raise ValueError(f'kid inconnu : "{kid}"')

    expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    sig_bytes = b64url_decode(sig)
    if not hmac.compare_digest(expected, sig_bytes):
        raise ValueError("Signature invalide")

    now = int(time.time())
    if payload.get("exp") and payload["exp"] < now:
        raise ValueError("Token expire")
    if payload.get("jti") in TOKEN_BLACKLIST:
        raise ValueError("Token revoque")

    return payload


def verify_rs256_hardened(token):
    if not RSA_PUBLIC_KEY:
        raise ValueError("Cles RSA non disponibles")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Format invalide")

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])

    if header.get("alg") != "RS256":
        raise ValueError(f'Algorithme refuse : "{header.get("alg")}" (seul RS256 est autorise ici)')

    try:
        RSA_PUBLIC_KEY.verify(
            b64url_decode(parts[2]),
            f"{parts[0]}.{parts[1]}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        raise ValueError("Signature RS256 invalide")

    now = int(time.time())
    if payload.get("exp") and payload["exp"] < now:
        raise ValueError("Token expire")

    return payload


def extract_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ValueError("Token manquant")
    return auth[7:]


@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Identifiants incorrects"}), 401
    token = sign_hs256_hardened({"username": username, "role": user["role"]})
    return jsonify({"token": token, "expires_in": TOKEN_TTL_SECONDS})


@app.route("/auth/logout", methods=["POST"])
def logout():
    try:
        payload = verify_hs256_hardened(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    TOKEN_BLACKLIST.add(payload.get("jti"))
    return jsonify({"message": "Token revoque avec succes"})


@app.route("/api/public")
def api_public():
    return jsonify({"message": "Endpoint public."})


@app.route("/api/user")
def api_user():
    try:
        user = verify_hs256_hardened(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    return jsonify({"message": "Donnees utilisateur", "user": user})


@app.route("/api/admin")
def api_admin():
    try:
        user = verify_hs256_hardened(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    if user.get("role") != "admin":
        return jsonify({"error": "Role admin requis"}), 403
    return jsonify({"message": "Acces admin", "user": user})


@app.route("/api/public-key")
def public_key():
    if not RSA_PUBLIC_PEM:
        return jsonify({"error": "Cles RSA non disponibles"}), 503
    return RSA_PUBLIC_PEM.decode(), 200, {"Content-Type": "text/plain"}


@app.route("/api/secret-rs256")
def api_secret_rs256():
    try:
        payload = verify_rs256_hardened(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    if payload.get("role") != "admin":
        return jsonify({"error": "Role admin requis"}), 403
    return jsonify({"message": "Acces RS256 securise accorde", "user": payload})


if __name__ == "__main__":
    print(f"\n[SERVEUR DURCI] http://localhost:{PORT}")
    print("  alg:none rejete")
    print("  Confusion RS256/HS256 impossible")
    print("  Secret fort (256 bits aleatoires)")
    print("  Expiration 15 min + liste noire + kid\n")
    app.run(host="0.0.0.0", port=PORT)
