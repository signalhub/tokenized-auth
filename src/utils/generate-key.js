const crypto = require('crypto').webcrypto;
const fs = require('fs');
const path = require('path');

const generateEncryptionSecretKey = async (secret, salt) => {
  const encoder = new TextEncoder();
  const secretKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    secretKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

const encryptSecretKey = async (secret, salt) => {
  const key = await generateEncryptionSecretKey(secret, salt);
  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const exportedKeyBuffer = Buffer.from(exportedKey);
  return exportedKeyBuffer.toString('base64');
};

const generateEnvFile = async (secret, envFilePath) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const encryptionKey = await encryptSecretKey(secret, salt);

  const envContent = `ENCRYPTION_KEY=${encryptionKey}\n`;

  fs.writeFileSync(envFilePath, envContent);
  console.log(`Encryption key generated and saved to ${envFilePath}.`);
};

const getArgFromArgs = (argName) => {
  const argIndex = process.argv.indexOf(argName);
  if (argIndex !== -1 && argIndex + 1 < process.argv.length) {
    return process.argv[argIndex + 1];
  }
  return null;
};

const secret = getArgFromArgs('--secret');
const envFilePath = getArgFromArgs('--output') || '.env';

if (secret) {
  generateEnvFile(secret, path.resolve(envFilePath)).then();
} else {
  console.error('Please provide a secret key using the --secret argument.');
  process.exit(1);
}

module.exports = {
  generateEnvFile,
};