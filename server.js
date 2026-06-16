const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

const HS256_SECRET = 'secret';

let RSA_PUBLIC_KEY  = null;
let RSA_PRIVATE_KEY = null;

try {
  RSA_PUBLIC_KEY  = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'),  'utf8');
  RSA_PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8');
} catch {
  console.warn('[WARN] Clés RSA manquantes — lancez d\'abord : node generate-keys.js');
  console.warn('[WARN] L\'endpoint /api/secret-rs256 sera désactivé.');
}

const USERS = {
  alice: { password: 'password123', role: 'user'  },
  admin: { password: 'admin123',    role: 'admin' },
};

function b64Encode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function b64Decode(str) {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
}

function signHS256(payload) {
  const header = b64Encode({ alg: 'HS256', typ: 'JWT' });
  const body   = b64Encode(payload);
  const sig    = crypto
    .createHmac('sha256', HS256_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${sig}`;
}

function signRS256(payload) {
  if (!RSA_PRIVATE_KEY) throw new Error('Clés RSA non disponibles');
  const header = b64Encode({ alg: 'RS256', typ: 'JWT' });
  const body   = b64Encode(payload);
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${body}`);
  const sig = signer.sign(RSA_PRIVATE_KEY, 'base64url');
  return `${header}.${body}.${sig}`;
}

function verifyVulnerable(token) {
  const parts = token.split('.');
  if (parts.length < 2) throw new Error('Token malformé');

  const header  = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);
  const sig     = parts[2] || '';

  if (header.alg === 'none') {
    console.log('\x1b[31m[VULN 1] Token alg:none accepté — aucune signature vérifiée !\x1b[0m');
    return payload;
  }

  if (header.alg === 'HS256') {
    const expected = crypto
      .createHmac('sha256', HS256_SECRET)
      .update(`${parts[0]}.${parts[1]}`)
      .digest('base64url');
    if (expected !== sig) throw new Error('Signature HS256 invalide');
    return payload;
  }

  throw new Error(`Algorithme non géré : ${header.alg}`);
}

function verifyConfusionEndpoint(token) {
  if (!RSA_PUBLIC_KEY) throw new Error('Clés RSA non disponibles');

  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Token malformé');

  const header  = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);
  const sig     = parts[2];
  const input   = `${parts[0]}.${parts[1]}`;

  if (header.alg === 'HS256') {
    const expected = crypto
      .createHmac('sha256', RSA_PUBLIC_KEY)
      .update(input)
      .digest('base64url');
    if (expected !== sig) throw new Error('Signature invalide (HS256/confusion)');
    console.log('\x1b[31m[VULN 2] Confusion RS256→HS256 exploitée — accès accordé !\x1b[0m');
    return payload;
  }

  if (header.alg === 'RS256') {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(input);
    if (!verifier.verify(RSA_PUBLIC_KEY, sig, 'base64url')) {
      throw new Error('Signature RS256 invalide');
    }
    return payload;
  }

  throw new Error(`Algorithme non géré : ${header.alg}`);
}

function extractToken(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) throw new Error('Token manquant');
  return auth.slice(7);
}

function requireAuth(req, res, next) {
  try {
    req.user = verifyVulnerable(extractToken(req));
    next();
  } catch (err) {
    res.status(401).json({ error: 'Non autorisé', detail: err.message });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Rôle admin requis' });
  }
  next();
}

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  const token = signHS256({ username, role: user.role, iat: Math.floor(Date.now() / 1000) });
  res.json({ token, note: 'Token HS256 signé avec un secret faible' });
});

app.post('/auth/login-rs256', (req, res) => {
  if (!RSA_PRIVATE_KEY) return res.status(503).json({ error: 'Clés RSA non disponibles' });
  const { username, password } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  const token = signRS256({ username, role: user.role, iat: Math.floor(Date.now() / 1000) });
  res.json({ token, note: 'Token RS256 signé avec la clé privée RSA' });
});

app.get('/api/public-key', (req, res) => {
  if (!RSA_PUBLIC_KEY) return res.status(503).json({ error: 'Clés RSA non disponibles' });
  res.type('text/plain').send(RSA_PUBLIC_KEY);
});

app.get('/api/public', (req, res) => {
  res.json({ message: 'Endpoint public — accessible sans token.' });
});

app.get('/api/user', requireAuth, (req, res) => {
  res.json({ message: 'Données utilisateur — token valide.', user: req.user });
});

app.get('/api/admin', requireAuth, requireAdmin, (req, res) => {
  res.json({
    message: '🔑 Accès admin accordé — données confidentielles.',
    secret_data: 'FLAG{jwt_alg_none_bypass}',
    user: req.user,
  });
});

app.get('/api/secret-rs256', (req, res) => {
  try {
    const payload = verifyConfusionEndpoint(extractToken(req));
    if (payload.role !== 'admin') {
      return res.status(403).json({ error: 'Rôle admin requis' });
    }
    res.json({
      message: '🔑 Accès RS256 accordé.',
      secret_data: 'FLAG{rs256_hs256_confusion}',
      user: payload,
    });
  } catch (err) {
    res.status(401).json({ error: 'Non autorisé', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n[SERVEUR VULNÉRABLE] http://localhost:${PORT}`);
  console.log('  POST /auth/login          → token HS256 (secret faible)');
  console.log('  POST /auth/login-rs256    → token RS256');
  console.log('  GET  /api/public          → public, sans auth');
  console.log('  GET  /api/user            → auth requise');
  console.log('  GET  /api/admin           → admin [VULN 1 : alg:none]');
  console.log('  GET  /api/public-key      → clé publique RSA');
  console.log('  GET  /api/secret-rs256    → RS256 [VULN 2 : confusion]');
  console.log(`\n  Secret HS256 : ${HS256_SECRET}`);
  console.log();
});
