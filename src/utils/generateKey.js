const fs = require('fs');
const crypto = require('crypto').webcrypto;

async function generateEncryptionKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const exportedKeyBuffer = Buffer.from(exportedKey);
  return exportedKeyBuffer.toString('base64');
}

async function generateEnv() {
  const secretKey = await generateEncryptionKey();
  const envContent = `\nENCRYPTION_KEY=${secretKey}\n`;
  fs.appendFileSync('.env', envContent);
}

generateEnv().then();