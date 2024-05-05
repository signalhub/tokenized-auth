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

  try {
    let envContent = '';

    if (fs.existsSync(envFilePath)) {
      envContent = fs.readFileSync(envFilePath, 'utf8');
    }

    const keyPattern = /^ENCRYPTION_KEY=.*/m;
    const newKeyLine = `ENCRYPTION_KEY=${encryptionKey}`;

    if (keyPattern.test(envContent)) {
      envContent = envContent.replace(keyPattern, newKeyLine);
    } else {
      envContent += `\n${newKeyLine}\n`;
    }

    fs.writeFileSync(envFilePath, envContent);
    console.log(`Encryption key updated in ${envFilePath}.`);
  } catch (error) {
    console.error('Error updating env file:', error);
    process.exit(1);
  }
};

const getArgFromArgs = (argName) => {
  const argIndex = process.argv.indexOf(argName);
  if (argIndex !== -1 && argIndex + 1 < process.argv.length) {
    return process.argv[argIndex + 1];
  }
  return null;
};

const secret = getArgFromArgs('--secret');
const outputArg = getArgFromArgs('--output');
const envFilePath = outputArg ? path.resolve(outputArg) : '.env';

const generateEnvFileAsync = async (secret, envFilePath) => {
  try {
    await generateEnvFile(secret, envFilePath);
  } catch (error) {
    console.error('Error generating env file:', error);
    process.exit(1);
  }
};

if (secret) {
  generateEnvFileAsync(secret, envFilePath).then();
} else {
  console.error('Please provide a secret key using the --secret argument.');
  process.exit(1);
}

module.exports = {
  generateEnvFile,
};
