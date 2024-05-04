# Tokenized auth

## Install

Run `npm i tokenized-auth` to install the library.

## How to use

### Generate key and encrypt it like a secret

```typescript
const key = await cryptoAuth.encryptKey();
```
Store generated key in the .env file

Or you can generate this key then you build your application just create a file `generate-env.js` in the root of your project with the following content:

```javascript
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
````
and update your `package.json` file:
```json
"scripts": {
  "build": "node generate-env.js && next build",
  // ...
}
```

