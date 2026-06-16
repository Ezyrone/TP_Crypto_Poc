# TP PoC Cryptographie — Sujet 12 : Analyse et exploitation d'une mauvaise gestion des JWT

**Étudiant :** [Jory GRZESZCZAK]  
**Niveau :** M2 AL ESGI Grenoble 
**Sujet :** 12 — Vulnérabilité JWT (difficulté : Normale)

---

## Sujet

Les JSON Web Tokens sont omniprésents dans les architectures d'authentification modernes.
Ce TP démontre trois vulnérabilités classiques :

| # | Vulnérabilité | Impact |
|---|---------------|--------|
| 1 | `alg:none` | Forge de token sans connaître le secret |
| 2 | Confusion RS256/HS256 | Forge de token avec la clé publique |
| 3 | Secret HS256 faible | Récupération du secret par force brute |

---

## Installation

**Prérequis :** Node.js ≥ 18

```bash
# Cloner le dépôt
git clone <url> && cd tp-poc-jwt

# Installer les dépendances (uniquement Express)
npm install

# Générer la paire de clés RSA-2048 (nécessaire pour la VULN 2)
node generate-keys.js
```

---

## Utilisation

### Lancer le serveur vulnérable

```bash
node server.js
# → http://localhost:3000
```

Ouvrez ensuite `http://localhost:3000` dans un navigateur pour l'interface interactive,
ou utilisez les scripts d'attaque en ligne de commande (voir ci-dessous).

### Comptes de test

| Utilisateur | Mot de passe | Rôle |
|-------------|-------------|------|
| `alice`     | `password123` | user |
| `admin`     | `admin123`    | admin |

### Endpoints API

| Méthode | Route | Description |
|---------|-------|-------------|
| POST | `/auth/login` | Login → token HS256 (secret faible) |
| POST | `/auth/login-rs256` | Login → token RS256 |
| GET | `/api/public` | Public, sans authentification |
| GET | `/api/user` | Authentification requise |
| GET | `/api/admin` | Rôle admin requis **[VULN 1]** |
| GET | `/api/public-key` | Clé publique RSA **[utilisée dans VULN 2]** |
| GET | `/api/secret-rs256` | RS256 requis **[VULN 2]** |

---

## Démonstrations des attaques

### Attaque 1 — alg:none (forge sans signature)

```bash
npm run attack:1
# ou
node attacks/1_alg_none.js
```

**Ce que ça fait :**
1. Connexion légitime avec `alice` (rôle : user)
2. Modification du header JWT : `"alg":"none"` + payload avec `"role":"admin"`
3. Suppression de la signature (token = `header.payload.`)
4. Accès à `/api/admin` — succès sans connaître le secret

**Condition de la vulnérabilité :** le serveur fait confiance au champ `alg` du header
au lieu d'imposer un algorithme côté serveur.

---

### Attaque 2 — Confusion RS256/HS256

```bash
npm run attack:2
# ou
node attacks/2_rs256_hs256.js
```

**Ce que ça fait :**
1. Récupération de la clé publique RSA via `/api/public-key` (publique, légitimement accessible)
2. Forge d'un token **HS256** signé avec cette clé publique comme secret HMAC
3. Accès à `/api/secret-rs256` — le serveur vulnérable l'accepte car il n'impose pas RS256

**Condition de la vulnérabilité :** le vérificateur utilise la même variable `key` pour les
deux algorithmes, sans forcer `{ algorithms: ['RS256'] }`. La bibliothèque `jsonwebtoken`
traitait autrefois une string PEM comme secret HMAC si le header disait `alg:HS256`.

---

### Attaque 3 — Force brute du secret HS256

```bash
npm run attack:3
# ou
node attacks/3_brute_force.js

# Avec rockyou.txt (recommandé) :
node attacks/3_brute_force.js --wordlist /usr/share/wordlists/rockyou.txt
```

**Ce que ça fait :**
1. Récupération d'un token JWT valide via login
2. Test offline de chaque mot candidat : `HMAC-SHA256(candidat, header.payload)`
3. Si la signature recalculée correspond → secret trouvé → forge d'un token admin

**Pourquoi c'est rapide :** la vérification HMAC ne nécessite aucun appel réseau.
Hashcat peut tester ~500 millions de combinaisons/seconde sur GPU.
Le secret `"secret"` est trouvé en quelques ms.

---

### Lancer le serveur durci (Partie 3)

```bash
node server-hardened.js
# → http://localhost:3001
```

Le serveur durci corrige les 3 vulnérabilités :
- Whitelist d'algorithmes (seul HS256 accepté)
- Secret fort généré aléatoirement (256 bits)
- Tokens avec expiration (15 min) + liste noire (logout)
- Vérificateurs RS256/HS256 séparés (pas de confusion possible)
- Support du champ `kid` pour la rotation de clés

> **Note Git :** ce serveur durci devrait être déployé depuis la branche `hardened`.
> Pour créer cette branche : `git checkout -b hardened && git add server-hardened.js && git commit -m "feat: serveur JWT durci"`

---

## Rapport — Questions du TP

### Structure d'un JWT et flux d'authentification

Un JWT est composé de trois parties encodées en Base64url, séparées par des points :

```
HEADER.PAYLOAD.SIGNATURE
```

- **Header** : algorithme de signature (`alg`) et type (`typ`).  
  Ex : `{"alg":"HS256","typ":"JWT"}`
- **Payload** : claims (assertions) : `sub`, `role`, `iat` (issued at), `exp` (expiration)…  
  Ex : `{"username":"alice","role":"user","iat":1700000000}`
- **Signature** : intégrité du header + payload.  
  Pour HS256 : `HMAC-SHA256(secret, base64url(header) + "." + base64url(payload))`

**Flux d'authentification standard :**
1. Client → `POST /auth/login { username, password }`
2. Serveur → vérifie les credentials → retourne un JWT signé
3. Client → stocke le token (mémoire ou `httpOnly cookie`)
4. Client → envoie `Authorization: Bearer <token>` à chaque requête protégée
5. Serveur → vérifie la signature, les claims (`exp`, `role`...) → accorde ou refuse l'accès

Le serveur **ne stocke pas** le token : la vérification est stateless (scalabilité horizontale).

---

### Détail de chaque vulnérabilité

#### VULN 1 — alg:none

**Principe :** La RFC 7518 définit `"none"` comme un algorithme valide signifiant
"pas de signature". Un serveur qui ne valide pas l'algorithme contre une whitelist
accepte des tokens non signés, permettant à quiconque de forger n'importe quel payload.

**Condition côté serveur :** faire confiance au champ `alg` du header JWT plutôt qu'imposer
un algorithme connu lors de la vérification.

**Exemples réels :** CVE-2015-9235 (jsonwebtoken < 4.2.2), auth0/node-jsonwebtoken avant fix.

**Correction :** `jwt.verify(token, secret, { algorithms: ['HS256'] })`

---

#### VULN 2 — Confusion RS256/HS256

**Principe :** Si un serveur expose sa clé publique RSA et vérifie les tokens avec
`jwt.verify(token, publicKeyPEM)` sans spécifier l'algorithme, certaines bibliothèques
utilisent le header `alg` pour décider comment interpréter la clé. Si `alg: HS256`,
la clé PEM est traitée comme secret HMAC — ce qui est contrôlable par l'attaquant.

**Condition côté serveur :** ne pas fixer `{ algorithms: ['RS256'] }` lors de la
vérification d'un endpoint censé n'accepter que du RS256.

**Construction de l'attaque :**
```
forged_token = base64url({alg:HS256}) + "." + base64url({role:admin}) + "."
             + HMAC-SHA256(publicKeyPEM, header + "." + payload)
```

**Correction :** utiliser des vérificateurs distincts avec whitelist d'algorithme explicite.

---

#### VULN 3 — Secret HS256 faible

**Principe :** HMAC-SHA256 peut être attaqué hors-ligne. L'attaquant intercepte un token
valide et teste des milliers de secrets candidats par seconde sans toucher le serveur.
Un secret présent dans un dictionnaire (rockyou.txt) est trouvé en quelques secondes.

**Condition côté serveur :** utiliser un secret court, devinable ou issu d'un dictionnaire.

**Capacité d'attaque (ordre de grandeur) :**
| Outil | Débit (HMAC-SHA256) |
|-------|---------------------|
| CPU mono-thread (Node.js) | ~500 000 H/s |
| Hashcat RTX 3090 | ~500 000 000 H/s |

rockyou.txt (~14 millions de mots) : cracké en < 1 seconde avec GPU.

**Correction :** `crypto.randomBytes(32).toString('hex')` → secret de 256 bits aléatoire.

---

### HS256 vs RS256/ES256 selon l'architecture

| Critère | HS256 (symétrique) | RS256/ES256 (asymétrique) |
|---------|-------------------|--------------------------|
| Clé | Secrète partagée | Paire publique/privée |
| Qui peut signer ? | Tout détenteur du secret | Seul le détenteur de la clé privée |
| Qui peut vérifier ? | Tout détenteur du secret | N'importe qui (clé publique) |
| Architecture idéale | Monolithique (un seul service) | Microservices, multi-serveurs |
| Rotation de clé | Nécessite de mettre à jour tous les services | Publie une nouvelle clé, révoque l'ancienne |
| Risque | Si le secret fuit, tout est compromis | La clé privée ne quitte jamais le serveur d'auth |

**Recommandation :** En microservices, préférer RS256/ES256 : seul le service d'authentification
détient la clé privée, tous les autres services vérifient avec la clé publique (JWKS endpoint).

---

### Recommandations OWASP sur la gestion des tokens de session

D'après [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
et [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) :

1. **Algorithme explicite** : fixer l'algorithme côté serveur, ne jamais lire `alg` du header.
2. **Secret fort** : ≥ 256 bits aléatoires générés avec un CSPRNG.
3. **Durée de vie courte** : `exp` ≤ 15 minutes pour les tokens d'accès.
4. **Refresh tokens** : tokens de renouvellement séparés, stockés `httpOnly`, révocables.
5. **Révocation** : blacklist ou versionnement du secret par utilisateur (`jti` + stockage).
6. **Transport** : HTTPS uniquement, jamais en URL (paramètre GET).
7. **Stockage client** : préférer `httpOnly cookie` à `localStorage` (protection XSS).
8. **Claims minimaux** : ne jamais inclure de données sensibles dans le payload (non chiffré).
9. **Rotation des clés** : support du `kid` pour permettre la rotation sans coupure.
10. **Audit** : logger les échecs de vérification de signature pour détecter les attaques.

---

## Structure du projet

```
.
├── server.js              # Serveur vulnérable (Partie 1 & 2)
├── server-hardened.js     # Serveur durci (Partie 3 — branche "hardened")
├── generate-keys.js       # Génération des clés RSA-2048
├── package.json
├── keys/
│   ├── private.pem        # Clé privée RSA (non committée)
│   └── public.pem         # Clé publique RSA
├── attacks/
│   ├── 1_alg_none.js      # Attaque alg:none
│   ├── 2_rs256_hs256.js   # Attaque confusion RS256/HS256
│   └── 3_brute_force.js   # Force brute du secret HS256
└── frontend/
    └── index.html         # Interface de démonstration
```
