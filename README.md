# TP PoC — Sujet 12 : Vulnérabilités JWT

**Jory GRZESZCZAK** — M2 AL, ESGI Grenoble

---

## Le projet en quelques mots

L'idée de ce TP c'est de montrer concrètement comment des JWT mal implémentés peuvent être exploités. J'ai monté un petit serveur Flask volontairement vulnérable, avec trois scripts d'attaque qui viennent taper dessus pour prouver que ça marche. Et à côté, un serveur durci qui montre comment corriger chaque faille.

Les trois vulnérabilités que je traite :

- **alg:none** — on vire la signature du token et le serveur l'accepte quand même
- **Confusion RS256/HS256** — on signe un token avec la clé publique du serveur comme secret HMAC, et il passe
- **Brute force du secret HS256** — le secret est trop faible, on le retrouve par dictionnaire sans même toucher au serveur

---

## Setup

Il faut Python 3.10+ et pip.

```bash
pip install -r requirements.txt
python generate_keys.py
```

La deuxième commande génère la paire RSA dans `keys/`. C'est nécessaire pour l'attaque 2.

---

## Lancer le serveur vulnérable

```bash
python server.py
```

Ça tourne sur `http://localhost:3000`. Il y a une interface web accessible directement dans le navigateur pour tester les attaques à la main, mais les scripts CLI sont plus complets.

**Comptes de test :**

| Utilisateur | Mot de passe | Rôle |
|-------------|-------------|------|
| `alice` | `password123` | user |
| `admin` | `admin123` | admin |

**Endpoints :**

| Route | Description |
|-------|-------------|
| `POST /auth/login` | Connexion, renvoie un token HS256 (secret : `"secret"`) |
| `POST /auth/login-rs256` | Connexion, renvoie un token RS256 |
| `GET /api/public` | Pas besoin de token |
| `GET /api/user` | Faut être authentifié |
| `GET /api/admin` | Faut être admin — **vulnérable à alg:none** |
| `GET /api/public-key` | Renvoie la clé publique RSA |
| `GET /api/secret-rs256` | Vérifie en RS256 — **vulnérable à la confusion d'algo** |

---

## Les attaques

### Attaque 1 — alg:none

```bash
python attacks/1_alg_none.py
```

Le script se connecte en tant qu'alice (user), récupère son token, puis le modifie : il met `"alg":"none"` dans le header et `"role":"admin"` dans le payload, et supprime la signature. Le serveur vulnérable lit l'algo depuis le header sans vérifier que c'est un algo autorisé, donc il accepte le token tel quel.

### Attaque 2 — Confusion RS256 / HS256

```bash
python attacks/2_rs256_hs256.py
```

Le script va chercher la clé publique RSA sur `/api/public-key` (elle est exposée, c'est normal en soi), puis s'en sert comme secret HMAC pour signer un token HS256 avec `role: admin`. Le serveur qui ne force pas l'algorithme RS256 sur cet endpoint accepte le token parce que la "vérification" HMAC passe — la clé publique est la même des deux côtés.

### Attaque 3 — Brute force HS256

```bash
python attacks/3_brute_force.py

# Avec un dictionnaire perso :
python attacks/3_brute_force.py --wordlist /chemin/vers/rockyou.txt
```

On récupère un token valide via un login normal, puis on essaie des secrets candidats en recalculant le HMAC-SHA256 à chaque fois. Aucun appel réseau nécessaire, c'est purement offline. Le secret `"secret"` tombe en 19 essais avec le dictionnaire intégré. Avec hashcat sur GPU, on peut tester environ 500 millions de candidats par seconde, ce qui rend n'importe quel secret "humain" vulnérable.

---

## Serveur durci

```bash
python server_hardened.py   # port 3001
```

C'est la version corrigée. Ce qui change :

- Seul `HS256` est accepté, `alg:none` est rejeté directement
- Le secret est généré aléatoirement au démarrage (256 bits, pas un mot du dico)
- Les tokens expirent au bout de 15 minutes
- Il y a une blacklist pour révoquer des tokens (endpoint `/auth/logout`)
- Support du champ `kid` dans le header pour pouvoir faire de la rotation de clés

---

## Comment un JWT fonctionne

Un JWT c'est trois parties séparées par des points :

```
base64url(header) . base64url(payload) . signature
```

Le header dit quel algo de signature est utilisé. Le payload contient les infos utiles (username, role, date d'expiration...). La signature garantit que personne n'a modifié les deux premières parties.

Un truc important : le payload n'est pas chiffré, juste encodé en base64. N'importe qui peut le lire. La sécurité repose uniquement sur la signature.

Le flux classique c'est :
1. Le client envoie ses identifiants
2. Le serveur vérifie et renvoie un JWT signé
3. Le client le stocke et l'envoie dans le header `Authorization: Bearer <token>` à chaque requête
4. Le serveur vérifie la signature et les claims sans rien stocker côté serveur

---

## Pourquoi ces failles existent

**alg:none** — La RFC 7518 définit `"none"` comme algo valide (pour les cas où la signature n'est pas nécessaire). Certaines bibliothèques l'implémentent, et si le serveur fait confiance au champ `alg` du header pour décider comment vérifier... il ne vérifie rien du tout. Ça a donné la CVE-2015-9235 sur jsonwebtoken < 4.2.2.

**Confusion RS256/HS256** — En RS256, on signe avec la clé privée et on vérifie avec la publique. Si le serveur appelle `verify(token, cle_publique)` sans imposer l'algo, et que l'attaquant met `HS256` dans le header, la bibliothèque utilise la clé publique comme secret HMAC. Et comme la clé publique est publique par définition, l'attaquant peut reproduire la même signature.

**Secret faible** — HMAC-SHA256 est rapide par design. C'est bien pour les perfs, mais ça veut dire qu'un attaquant peut tester des milliards de candidats. L'attaque est totalement offline : un seul token intercepté suffit. Pas besoin de toucher au serveur, pas de rate limiting possible.

---

## HS256 vs RS256 / ES256

HS256 utilise un secret partagé : tout service qui peut vérifier un token peut aussi en créer. C'est ok pour une archi simple avec un seul serveur.

RS256 et ES256 utilisent une paire de clés. Seul le service d'auth a la clé privée. Les autres services vérifient avec la clé publique sans pouvoir émettre de tokens. C'est ce qu'il faut en microservices.

ES256 (ECDSA P-256) est généralement préférable à RS256 : signatures plus courtes, plus rapide, même niveau de sécurité.

---

## Recommandations OWASP

D'après le JWT Security Cheat Sheet :

1. Toujours fixer l'algorithme côté serveur, ne jamais se baser sur le header du token
2. Secret d'au moins 256 bits aléatoires, stocké dans une variable d'env ou un secret manager
3. Access tokens de courte durée (15 min), avec un mécanisme de refresh à part
4. Rien de sensible dans le payload (c'est lisible par tout le monde)
5. Stocker le token dans un cookie `httpOnly` plutôt que dans `localStorage` (protection XSS)
6. Prévoir un mécanisme de révocation (blacklist par `jti` ou versionnement de secret)
7. Rotation régulière des clés avec support du `kid`

---

## Arborescence

```
.
├── server.py
├── server_hardened.py
├── generate_keys.py
├── requirements.txt
├── attacks/
│   ├── 1_alg_none.py
│   ├── 2_rs256_hs256.py
│   └── 3_brute_force.py
└── frontend/
    └── index.html
```
