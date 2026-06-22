import json
import time
import hmac
import hashlib
import base64
import os

from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

app = Flask(__name__, static_folder="frontend", static_url_path="")
PORT = 3000

HS256_SECRET = "secret"

RSA_PUBLIC_KEY = None
RSA_PRIVATE_KEY = None
RSA_PUBLIC_PEM = None

keys_dir = os.path.join(os.path.dirname(__file__), "keys")
try:
    with open(os.path.join(keys_dir, "public.pem"), "rb") as f:
        RSA_PUBLIC_PEM = f.read()
        RSA_PUBLIC_KEY = serialization.load_pem_public_key(RSA_PUBLIC_PEM)
    with open(os.path.join(keys_dir, "private.pem"), "rb") as f:
        RSA_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)
except FileNotFoundError:
    print("[WARN] Cles RSA manquantes — lancez d'abord : python generate_keys.py")
    print("[WARN] L'endpoint /api/secret-rs256 sera desactive.")

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


def sign_hs256(payload):
    header = b64url_encode_json({"alg": "HS256", "typ": "JWT"})
    body = b64url_encode_json(payload)
    sig = hmac.new(HS256_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64url_encode(sig)}"


def sign_rs256(payload):
    if not RSA_PRIVATE_KEY:
        raise RuntimeError("Cles RSA non disponibles")
    header = b64url_encode_json({"alg": "RS256", "typ": "JWT"})
    body = b64url_encode_json(payload)
    message = f"{header}.{body}".encode()
    signature = RSA_PRIVATE_KEY.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{b64url_encode(signature)}"


def verify_vulnerable(token):
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Token malformé")

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])
    sig = parts[2] if len(parts) > 2 else ""

    if header.get("alg") == "none":
        print("\033[31m[VULN 1] Token alg:none accepte — aucune signature verifiee !\033[0m")
        return payload

    if header.get("alg") == "HS256":
        expected = b64url_encode(
            hmac.new(HS256_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        )
        if expected != sig:
            raise ValueError("Signature HS256 invalide")
        return payload

    if header.get("alg") == "RS256":
        if not RSA_PUBLIC_KEY:
            raise ValueError("Cles RSA non disponibles")
        try:
            RSA_PUBLIC_KEY.verify(
                b64url_decode(sig),
                f"{parts[0]}.{parts[1]}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception:
            raise ValueError("Signature RS256 invalide")
        return payload

    raise ValueError(f"Algorithme non gere : {header.get('alg')}")


def verify_confusion_endpoint(token):
    if not RSA_PUBLIC_KEY:
        raise ValueError("Cles RSA non disponibles")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token malformé")

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])
    sig = parts[2]
    input_data = f"{parts[0]}.{parts[1]}"

    if header.get("alg") == "HS256":
        expected = b64url_encode(
            hmac.new(RSA_PUBLIC_PEM, input_data.encode(), hashlib.sha256).digest()
        )
        if expected != sig:
            raise ValueError("Signature invalide (HS256/confusion)")
        print("\033[31m[VULN 2] Confusion RS256->HS256 exploitee — acces accorde !\033[0m")
        return payload

    if header.get("alg") == "RS256":
        try:
            RSA_PUBLIC_KEY.verify(
                b64url_decode(sig),
                input_data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception:
            raise ValueError("Signature RS256 invalide")
        return payload

    raise ValueError(f"Algorithme non gere : {header.get('alg')}")


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
    token = sign_hs256({"username": username, "role": user["role"], "iat": int(time.time())})
    return jsonify({"token": token, "note": "Token HS256 signe avec un secret faible"})


@app.route("/auth/login-rs256", methods=["POST"])
def login_rs256():
    if not RSA_PRIVATE_KEY:
        return jsonify({"error": "Cles RSA non disponibles"}), 503
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Identifiants incorrects"}), 401
    token = sign_rs256({"username": username, "role": user["role"], "iat": int(time.time())})
    return jsonify({"token": token, "note": "Token RS256 signe avec la cle privee RSA"})


@app.route("/api/public-key")
def public_key():
    if not RSA_PUBLIC_PEM:
        return jsonify({"error": "Cles RSA non disponibles"}), 503
    return RSA_PUBLIC_PEM.decode(), 200, {"Content-Type": "text/plain"}


@app.route("/api/public")
def api_public():
    return jsonify({"message": "Endpoint public — accessible sans token."})


@app.route("/api/user")
def api_user():
    try:
        user = verify_vulnerable(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    return jsonify({"message": "Donnees utilisateur — token valide.", "user": user})


@app.route("/api/admin")
def api_admin():
    try:
        user = verify_vulnerable(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    if user.get("role") != "admin":
        return jsonify({"error": "Role admin requis"}), 403
    return jsonify({
        "message": "Acces admin accorde — donnees confidentielles.",
        "secret_data": "FLAG{jwt_alg_none_bypass}",
        "user": user,
    })


@app.route("/api/secret-rs256")
def api_secret_rs256():
    try:
        payload = verify_confusion_endpoint(extract_token())
    except ValueError as e:
        return jsonify({"error": "Non autorise", "detail": str(e)}), 401
    if payload.get("role") != "admin":
        return jsonify({"error": "Role admin requis"}), 403
    return jsonify({
        "message": "Acces RS256 accorde.",
        "secret_data": "FLAG{rs256_hs256_confusion}",
        "user": payload,
    })


if __name__ == "__main__":
    print(f"\n[SERVEUR VULNERABLE] http://localhost:{PORT}")
    print("  POST /auth/login          -> token HS256 (secret faible)")
    print("  POST /auth/login-rs256    -> token RS256")
    print("  GET  /api/public          -> public, sans auth")
    print("  GET  /api/user            -> auth requise")
    print("  GET  /api/admin           -> admin [VULN 1 : alg:none]")
    print("  GET  /api/public-key      -> cle publique RSA")
    print("  GET  /api/secret-rs256    -> RS256 [VULN 2 : confusion]")
    print(f"\n  Secret HS256 : {HS256_SECRET}\n")
    app.run(host="0.0.0.0", port=PORT)
