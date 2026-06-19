# TP PoC — Sujet 12 : Vulnérabilités JWT

**Étudiant :** Jory GRZESZCZAK  
**Formation :** M2 AL — ESGI Grenoble  
**Sujet :** 12 — Analyse et exploitation d'une mauvaise gestion des JWT

---

## Présentation

Ce projet est une preuve de concept illustrant trois vulnérabilités classiques des JSON Web Tokens. Les JWT sont aujourd'hui très répandus dans les architectures d'authentification, mais une implémentation incorrecte peut les rendre entièrement contournables. Les trois vulnérabilités couvertes sont :

- **alg:none** — suppression de la signature, le serveur accepte le token sans vérification
- **Confusion RS256/HS256** — utilisation de la clé publique du serveur comme secret HMAC pour forger un token valide
- **Secret HS256 faible** — récupération du secret par attaque dictionnaire, entièrement offline

Chaque vulnérabilité est accompagnée d'un script d'attaque autonome et d'une explication dans ce rapport.

---

## Installation

**Prérequis :** Node.js 18 ou supérieur.

```bash
npm install
node generate-keys.js   # génère la paire de clés RSA (nécessaire pour la vulnérabilité 2)
```

---

## Utilisation

### Lancer le serveur vulnérable

```bash
node server.js
```

Le serveur démarre sur `http://localhost:3000`. Une interface web est accessible à cette adresse pour tester les attaques depuis un navigateur, mais les scripts CLI sont plus complets et plus lisibles.

**Comptes de test :**

| Utilisateur | Mot de passe | Rôle |
|-------------|-------------|------|
| `alice` | `password123` | user |
| `admin` | `admin123` | admin |

**Endpoints disponibles :**

| Route | Description |
|-------|-------------|
| `POST /auth/login` | Connexion → token HS256 (secret : `"secret"`) |
| `POST /auth/login-rs256` | Connexion → token RS256 |
| `GET /api/public` | Accessible sans authentification |
| `GET /api/user` | Authentification requise |
| `GET /api/admin` | Rôle admin requis — **vulnérable à alg:none** |
| `GET /api/public-key` | Clé publique RSA exposée |
| `GET /api/secret-rs256` | RS256 requis — **vulnérable à la confusion d'algorithme** |

---

## Démonstration des attaques

### Attaque 1 — alg:none

```bash
node attacks/1_alg_none.js
```

Le script se connecte avec le compte `alice` (rôle : user), récupère le token, puis le modifie : le header passe à `"alg":"none"`, le payload est modifié pour indiquer `"role":"admin"`, et la signature est supprimée. Le serveur vulnérable, qui fait confiance au champ `alg` du header sans le valider, accepte ce token et accorde l'accès à `/api/admin`.

### Attaque 2 — Confusion RS256/HS256

```bash
node attacks/2_rs256_hs256.js
```

Le script récupère la clé publique RSA exposée par `/api/public-key`, puis forge un token HS256 en utilisant cette clé comme secret HMAC. Le serveur vulnérable, qui ne fixe pas l'algorithme attendu lors de la vérification, accepte ce token sur l'endpoint `/api/secret-rs256` qui devrait pourtant n'accepter que du RS256.

### Attaque 3 — Force brute du secret HS256

```bash
node attacks/3_brute_force.js

# Avec rockyou.txt :
node attacks/3_brute_force.js --wordlist /usr/share/wordlists/rockyou.txt
```

Le script récupère un token valide via une connexion normale, puis teste des secrets candidats en recalculant le HMAC à chaque itération — sans aucun appel réseau. Le secret `"secret"` est retrouvé en 19 essais. La différence de vitesse avec bcrypt est significative : HMAC-SHA256 permet environ 500 millions de tentatives par seconde sur GPU, contre environ 20 000 pour bcrypt. Cela illustre pourquoi un secret faible est une vulnérabilité critique.

---

## Serveur durci — Partie 3

```bash
node server-hardened.js   # port 3001
```

Ce fichier constitue la version corrigée du serveur. Les modifications apportées :

- Whitelist d'algorithmes explicite : seul `HS256` est accepté, `alg:none` est rejeté
- Secret généré aléatoirement au démarrage (256 bits)
- Expiration des tokens à 15 minutes (`exp` claim)
- Liste noire de tokens révoqués (logout)
- Support du champ `kid` pour la rotation de clés sans interruption de service

> Ce fichier constitue la version production-ready du serveur, corrigeant toutes les vulnérabilités démontrées.

---

## Rapport

### Structure d'un JWT et flux d'authentification

Un JWT est composé de trois parties encodées en Base64url, séparées par des points :

```
base64url(header) . base64url(payload) . signature
```

Le header indique l'algorithme de signature utilisé. Le payload contient les claims : identifiant utilisateur, rôle, date d'émission (`iat`), date d'expiration (`exp`). La signature garantit l'intégrité des deux premières parties.

Un point souvent mal compris : le payload n'est pas chiffré, seulement encodé. N'importe qui peut le décoder et lire son contenu. La sécurité repose entièrement sur la signature, pas sur la confidentialité du payload.

**Flux d'authentification standard :**
1. Le client envoie ses identifiants via `POST /auth/login`
2. Le serveur les vérifie et retourne un JWT signé
3. Le client stocke le token et l'envoie dans le header `Authorization: Bearer <token>` à chaque requête protégée
4. Le serveur vérifie la signature et les claims — sans stocker quoi que ce soit côté serveur, ce qui rend JWT stateless

---

### Analyse des vulnérabilités

**alg:none** — La RFC 7518 définit `"none"` comme un algorithme valide pour les contextes où la signature est inutile. Certaines bibliothèques l'ont implémenté, et un serveur qui lit l'algorithme depuis le header sans le comparer à une whitelist accepte des tokens non signés. La CVE-2015-9235 (jsonwebtoken < 4.2.2) illustre un cas réel. La correction tient en un paramètre : `{ algorithms: ['HS256'] }`.

**Confusion RS256/HS256** — RS256 repose sur une paire de clés asymétrique : signature avec la clé privée, vérification avec la clé publique. Lorsqu'un développeur appelle `jwt.verify(token, publicKeyPEM)` sans préciser l'algorithme, certaines bibliothèques JWT lisent le champ `alg` du header pour décider comment interpréter la clé. Si ce header indique `HS256`, la string PEM est utilisée comme secret HMAC. La clé publique étant publique par définition, l'attaquant peut reproduire exactement la même signature. La correction consiste à utiliser des vérificateurs distincts avec un algorithme explicitement imposé par endpoint.

**Secret HS256 faible** — HMAC-SHA256 est conçu pour être rapide, ce qui est une qualité pour la performance mais un problème pour la résistance aux attaques. L'attaque est entièrement offline : à partir d'un seul token intercepté (obtenu via une connexion légitime), il est possible de tester des milliards de secrets candidats sans que le serveur ne soit sollicité ni alerté. Avec Hashcat sur GPU, la totalité de rockyou.txt (environ 14 millions de mots) est testée en moins d'une seconde. Un secret de 256 bits aléatoires rend cette attaque infaisable.

---

### HS256 vs RS256/ES256

HS256 repose sur un secret partagé : tout service capable de vérifier un token peut aussi en émettre un. Cette approche convient aux architectures monolithiques où un seul service gère les tokens de bout en bout.

RS256 et ES256 utilisent une paire de clés asymétrique. Seul le service d'authentification possède la clé privée et peut émettre des tokens. Les autres services vérifient avec la clé publique, sans pouvoir en créer. Cette séparation est essentielle en microservices : la compromission d'un service ne suffit pas à forger des tokens valides.

ES256 (ECDSA sur P-256) est généralement préférable à RS256 : signatures plus courtes, génération plus rapide, niveau de sécurité équivalent.

---

### Recommandations OWASP

D'après l'OWASP JWT Security Cheat Sheet et le Session Management Cheat Sheet :

1. Fixer l'algorithme attendu côté serveur et ne jamais lire `alg` depuis le header pour décider quoi vérifier
2. Utiliser un secret d'au moins 256 bits aléatoires, chargé depuis une variable d'environnement ou un secret manager
3. Limiter la durée de vie des access tokens (15 minutes recommandé), avec un mécanisme de refresh séparé
4. Ne jamais inclure de données sensibles dans le payload, celui-ci étant lisible par quiconque intercepte le token
5. Stocker le token côté client dans un cookie `httpOnly` plutôt que dans `localStorage` (résistance aux attaques XSS)
6. Implémenter un mécanisme de révocation : blacklist par `jti`, ou versionnement de secret par utilisateur
7. Prévoir la rotation régulière des clés avec support du champ `kid` pour éviter toute interruption de service

---

## Structure du projet

```
.
├── server.js              
├── server-hardened.js     
├── generate-keys.js       
├── attacks/
│   ├── 1_alg_none.js
│   ├── 2_rs256_hs256.js
│   └── 3_brute_force.js
└── frontend/
    └── index.html        
```
