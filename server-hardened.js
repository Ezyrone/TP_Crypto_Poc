/**
 * TP PoC Cryptographie — Sujet 12 : Vulnérabilités JWT
 * =====================================================
 * SERVEUR DURCI — Partie 3
 * (À déployer depuis la branche Git "hardened")
 *
 * Corrections appliquées face aux 3 vulnérabilités :
 *
 *   ✅ VULN 1 corrigée — Whitelist d'algorithmes : seul HS256 est accepté.
 *      Tout token avec "alg":"none" ou un algorithme non attendu est rejeté.
 *
 *   ✅ VULN 2 corrigée — Algorithme forcé côté serveur : la vérification
 *      HS256 et RS256 utilisent des fonctions séparées avec des clés séparées.
 *      Un token HS256 ne peut jamais passer la vérification RS256 et vice-versa.
 *
 *   ✅ VULN 3 corrigée — Secret fort : généré aléatoirement (256 bits)
 *      au démarrage. Résistant à toute attaque par dictionnaire.
 *
 * Fonctionnalités supplémentaires :
 *   - Expiration des tokens (exp : 15 minutes)
 *   - Liste noire de tokens révoqués (logout)
 *   - Support du champ "kid" pour la rotation de clés
 */

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3001; // Port différent pour coexister avec le serveur vulnérable

app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

// ─── CONFIGURATION SÉCURISÉE ─────────────────────────────────────────────────

const TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes

// CORRECTION VULN 3 : secret aléatoire fort (256 bits), généré au démarrage.
// En production, charger depuis une variable d'environnement ou un secret manager.
const HS256_SECRET_STRONG = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
console.log('[DURCI] Secret HS256 (durée de vie du processus) :', HS256_SECRET_STRONG);

// Support de la rotation de clés via "kid" (Key ID).
// En production : charger depuis une config ou un KMS.
const KEY_STORE = {
  'key-v1': crypto.randomBytes(32).toString('hex'),
  'key-v2': HS256_SECRET_STRONG, // clé active
};
const CURRENT_KID = 'key-v2';

// CORRECTION VULN 2 : clés RSA séparées, algorithme forcé explicitement.
let RSA_PUBLIC_KEY  = null;
let RSA_PRIVATE_KEY = null;
try {
  RSA_PUBLIC_KEY  = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'),  'utf8');
  RSA_PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8');
} catch {
  console.warn('[WARN] Clés RSA manquantes — /api/secret-rs256 désactivé.');
}

// Liste noire de tokens révoqués (logout, compromission…)
// En production : utiliser Redis avec TTL automatique.
const TOKEN_BLACKLIST = new Set();

const USERS = {
  alice: { password: 'password123', role: 'user'  },
  admin: { password: 'admin123',    role: 'admin' },
};

// ─── UTILITAIRES JWT SÉCURISÉS ───────────────────────────────────────────────

function b64Encode(obj) { return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
function b64Decode(str) { return JSON.parse(Buffer.from(str, 'base64url').toString('utf8')); }

/** Signe un token HS256 avec le kid actif et une expiration. */
function signHS256Hardened(payload) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64Encode({ alg: 'HS256', typ: 'JWT', kid: CURRENT_KID });
  const body   = b64Encode({ ...payload, iat: now, exp: now + TOKEN_TTL_SECONDS });
  const secret = KEY_STORE[CURRENT_KID];
  const sig    = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

/**
 * VÉRIFICATION SÉCURISÉE HS256
 *
 * - Whitelist d'algorithmes : seul HS256 accepté (CORRECTION VULN 1 & 2)
 * - Support du kid pour la rotation de clés
 * - Vérification de l'expiration (exp)
 * - Vérification de la liste noire
 */
function verifyHS256Hardened(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Format invalide');

  const header  = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);
  const sig     = parts[2];

  // CORRECTION VULN 1 & 2 : whitelist stricte, alg:none impossible
  if (header.alg !== 'HS256') {
    throw new Error(`Algorithme refusé : "${header.alg}" (seul HS256 est autorisé)`);
  }

  // Support du kid pour la rotation
  const kid    = header.kid || CURRENT_KID;
  const secret = KEY_STORE[kid];
  if (!secret) throw new Error(`kid inconnu : "${kid}"`);

  // Vérification HMAC
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${parts[0]}.${parts[1]}`)
    .digest('base64url');
  if (expected !== sig) throw new Error('Signature invalide');

  // Vérification de l'expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error('Token expiré');
  }

  // Vérification de la liste noire
  if (TOKEN_BLACKLIST.has(token)) {
    throw new Error('Token révoqué');
  }

  return payload;
}

/**
 * VÉRIFICATION SÉCURISÉE RS256
 *
 * - Algorithme forcé à RS256 (CORRECTION VULN 2)
 * - Jamais mélangé avec HS256
 */
function verifyRS256Hardened(token) {
  if (!RSA_PUBLIC_KEY) throw new Error('Clés RSA non disponibles');

  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Format invalide');

  const header  = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);

  // CORRECTION VULN 2 : seul RS256 accepté pour cet endpoint
  if (header.alg !== 'RS256') {
    throw new Error(`Algorithme refusé : "${header.alg}" (seul RS256 est autorisé ici)`);
  }

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(`${parts[0]}.${parts[1]}`);
  if (!verifier.verify(RSA_PUBLIC_KEY, parts[2], 'base64url')) {
    throw new Error('Signature RS256 invalide');
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Token expiré');

  return payload;
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

function extractToken(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) throw new Error('Token manquant');
  return auth.slice(7);
}

function requireAuth(req, res, next) {
  try {
    req.user = verifyHS256Hardened(extractToken(req));
    next();
  } catch (err) {
    res.status(401).json({ error: 'Non autorisé', detail: err.message });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Rôle admin requis' });
  next();
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  const token = signHS256Hardened({ username, role: user.role });
  res.json({ token, expires_in: TOKEN_TTL_SECONDS });
});

// Révocation de token (logout)
app.post('/auth/logout', requireAuth, (req, res) => {
  const token = extractToken(req);
  TOKEN_BLACKLIST.add(token);
  res.json({ message: 'Token révoqué avec succès' });
});

app.get('/api/public',     (req, res) => res.json({ message: 'Endpoint public.' }));
app.get('/api/user',       requireAuth, (req, res) => res.json({ message: 'Données utilisateur', user: req.user }));
app.get('/api/admin',      requireAuth, requireAdmin, (req, res) =>
  res.json({ message: 'Accès admin', user: req.user }));

app.get('/api/public-key', (req, res) => {
  if (!RSA_PUBLIC_KEY) return res.status(503).json({ error: 'Clés RSA non disponibles' });
  res.type('text/plain').send(RSA_PUBLIC_KEY);
});

// Endpoint RS256 — vérification stricte, pas de confusion possible
app.get('/api/secret-rs256', (req, res) => {
  try {
    const payload = verifyRS256Hardened(extractToken(req));
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Rôle admin requis' });
    res.json({ message: 'Accès RS256 sécurisé accordé', user: payload });
  } catch (err) {
    res.status(401).json({ error: 'Non autorisé', detail: err.message });
  }
});

// ─── DÉMARRAGE ───────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n[SERVEUR DURCI] http://localhost:${PORT}`);
  console.log('Corrections actives :');
  console.log('  ✅ alg:none rejeté (whitelist HS256 uniquement)');
  console.log('  ✅ Confusion RS256/HS256 impossible (vérificateurs séparés)');
  console.log('  ✅ Secret HS256 fort (256 bits aléatoires)');
  console.log('  ✅ Expiration des tokens (TTL 15 min)');
  console.log('  ✅ Liste noire (logout)');
  console.log('  ✅ Support kid pour rotation de clés');
  console.log();
});
