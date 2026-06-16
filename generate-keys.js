/**
 * Génère une paire de clés RSA-2048 pour les démonstrations JWT.
 * Les clés sont sauvegardées dans ./keys/ (non committées dans Git).
 *
 * Usage : node generate-keys.js
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir);

console.log('Génération de la paire de clés RSA-2048...');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(keysDir, 'public.pem'),  publicKey);

console.log('✓ keys/private.pem  (GARDEZ SECRÈTE)');
console.log('✓ keys/public.pem   (exposée par /api/public-key)');
