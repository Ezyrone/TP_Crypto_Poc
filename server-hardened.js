const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3001;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

const TOKEN_TTL_SECONDS   = 15 * 60;
const HS256_SECRET_STRONG = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

console.log('[DURCI] Secret HS256 :', HS256_SECRET_STRONG);

const KEY_STORE = {
  'key-v1': crypto.randomBytes(32).toString('hex'),
  'key-v2': HS256_SECRET_STRONG,
};
const CURRENT_KID = 'key-v2';

let RSA_PUBLIC_KEY = null;
try {
  RSA_PUBLIC_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');
} catch {
  console.warn('[WARN] Clés RSA manquantes — /api/secret-rs256 désactivé.');
}

const TOKEN_BLACKLIST = new Set();

const USERS = {
  alice: { password: 'password123', role: 'user'  },
  admin: { password: 'admin123',    role: 'admin' },
};

function b64Encode(obj) { return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
function b64Decode(str) { return JSON.parse(Buffer.from(str, 'base64url').toString('utf8')); }

function signHS256Hardened(payload) {
  const now    = Math.floor(Date.now() / 1000);
  const header = b64Encode({ alg: 'HS256', typ: 'JWT', kid: CURRENT_KID });
  const body   = b64Encode({ ...payload, jti: crypto.randomUUID(), iat: now, exp: now + TOKEN_TTL_SECONDS });
  const secret = KEY_STORE[CURRENT_KID];
  const sig    = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyHS256Hardened(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Format invalide');

  const header  = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);
  const sig     = parts[2];

  if (header.alg !== 'HS256') {
    throw new Error(`Algorithme refusé : "${header.alg}" (seul HS256 est autorisé)`);
  }

  const kid    = header.kid || CURRENT_KID;
  const secret = KEY_STORE[kid];
  if (!secret) throw new Error(`kid inconnu : "${kid}"`);

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${parts[0]}.${parts[1]}`)
    .digest('base64url');
  if (expected !== sig) throw new Error('Signature invalide');

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Token expiré');
  if (TOKEN_BLACKLIST.has(payload.jti)) throw new Error('Token révoqué');

  return payload;
}

function verifyRS256Hardened(token) {
  if (!RSA_PUBLIC_KEY) throw new Error('Clés RSA non disponibles');

  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Format invalide');

  const header  = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);

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

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  const token = signHS256Hardened({ username, role: user.role });
  res.json({ token, expires_in: TOKEN_TTL_SECONDS });
});

app.post('/auth/logout', requireAuth, (req, res) => {
  TOKEN_BLACKLIST.add(req.user.jti);
  res.json({ message: 'Token révoqué avec succès' });
});

app.get('/api/public',     (req, res) => res.json({ message: 'Endpoint public.' }));
app.get('/api/user',       requireAuth, (req, res) => res.json({ message: 'Données utilisateur', user: req.user }));
app.get('/api/admin',      requireAuth, requireAdmin, (req, res) => res.json({ message: 'Accès admin', user: req.user }));

app.get('/api/public-key', (req, res) => {
  if (!RSA_PUBLIC_KEY) return res.status(503).json({ error: 'Clés RSA non disponibles' });
  res.type('text/plain').send(RSA_PUBLIC_KEY);
});

app.get('/api/secret-rs256', (req, res) => {
  try {
    const payload = verifyRS256Hardened(extractToken(req));
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Rôle admin requis' });
    res.json({ message: 'Accès RS256 sécurisé accordé', user: payload });
  } catch (err) {
    res.status(401).json({ error: 'Non autorisé', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n[SERVEUR DURCI] http://localhost:${PORT}`);
  console.log('  ✅ alg:none rejeté');
  console.log('  ✅ Confusion RS256/HS256 impossible');
  console.log('  ✅ Secret fort (256 bits aléatoires)');
  console.log('  ✅ Expiration 15 min + liste noire + kid');
  console.log();
});
