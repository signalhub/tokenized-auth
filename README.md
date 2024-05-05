# Crypto auth data

## Install

Run `npm i crypto-auth-data` to install the library.

## How to use

### 1. Generate key and encrypt it like a secret

Add script to your `package.json` file:
```json
"scripts": {
  "generate-key": "node node_modules/crypto-auth-data/src/utils/generate-key.js -- --secret \"my-secret-phrase\" --output \"path/to/project/.env\""
},
```
in the .env file you will have the following variables
```env
ENCRYPTION_KEY=eoEG4sJQxPHurfzgYSJ7Vmlwsk7poKXiHlq8MQxvjp4=
```

### 2. Decrypt generated key

```typescript
import { cryptoData } from 'crypto-auth-data';

const salt = new Uint8Array(16);
const key = process.env.ENCRYPTION_KEY
const decryptedKey = await cryptoData.decryptSecretKey(key, salt);

```

### 3. Encrypt JWT data

```typescript
if (decryptedKey) {
  const encryptJWT = await cryptoData.encryptJWT(response.token.accessToken, decryptedKey); // save it to localStorage
}

```

### 4. Decrypt JWT data for every request

Get encryptJWT from localStorage and decrypt it

```typescript
const accessToken = await cryptoData.decryptJWT(encryptJWT, decryptedKey);
headers.set("Authorization", `Bearer ${accessToken}`);

````
