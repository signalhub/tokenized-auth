import { cryptoData } from './encription';
import { describe } from 'vitest';

describe('generateEncryptionKey', () => {
  it('should return a text key', async () => {
    // as util method, should not be used in production
    const key = await cryptoData.generateEncryptionKey();
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(key.extractable).toBe(true);
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
  });
});

describe('encryptKey', () => {
  it('should return a text key', async () => {
    const key = await cryptoData.encryptKey();
    expect(typeof key).toBe('string');
    expect(key).not.toBe('');
    expect(() => {
      Buffer.from(key, 'base64');
    }).not.toThrow();
    const decodedKey = Buffer.from(key, 'base64');
    expect(decodedKey.length).toBe(32);
  });
});

describe('decryptKey', () => {
  it('should return a valid CryptoKey', async () => {
    const encryptedKey = "FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoData.decryptKey(encryptedKey);

    expect(decryptedKey).toBeInstanceOf(CryptoKey);
    expect(decryptedKey.type).toBe('secret');
    expect(decryptedKey.extractable).toBe(true);
    expect(decryptedKey.algorithm).toEqual({ name: 'AES-GCM', length: 256 });
    expect(decryptedKey.usages).toEqual(['encrypt', 'decrypt']);
  });

  it('should throw an error for invalid encrypted key', async () => {
    const invalidEncryptedKey = "invalid_key";

    await expect(cryptoData.decryptKey(invalidEncryptedKey)).rejects.toThrow();
  });
});

describe('encryptJWT', () => {
  it('should encrypt and decrypt a JWT successfully', async () => {
    const encryptedKey = "FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoData.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoData.encryptJWT(jwt, decryptedKey);
    const decryptedJWT = await cryptoData.decryptJWT(encryptedJWT, decryptedKey);

    expect(decryptedJWT).toEqual(jwt);
  });
});

describe('decryptJWT', () => {
  it('should decrypt the encrypted JWT and return the original JWT', async () => {
    const encryptedKey = "FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoData.decryptKey(encryptedKey);
    const originalJWT = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoData.encryptJWT(originalJWT, decryptedKey);
    const decryptedJWT = await cryptoData.decryptJWT(encryptedJWT, decryptedKey);

    expect(decryptedJWT).toEqual(originalJWT);
  });
});

describe('encryptSecretKey', () => {
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  console.log('salt', salt);

  it('should encrypt the secret key correctly', async () => {
    const secret = 'mySecretKey';
    const encryptedKey = await cryptoData.encryptSecretKey(secret, salt);

    expect(typeof encryptedKey).toBe('string');
    expect(encryptedKey).not.toBe('');
  });

  it('should return different encrypted keys for different secrets', async () => {
    const secret1 = 'mySecretKey1';
    const secret2 = 'mySecretKey2';
    const encryptedKey1 = await cryptoData.encryptSecretKey(secret1, salt);
    const encryptedKey2 = await cryptoData.encryptSecretKey(secret2, salt);

    expect(encryptedKey1).not.toBe(encryptedKey2);
  });

  it('should return different encrypted keys for different salts', async () => {
    const secret = 'mySecretKey';
    const salt1 = salt;
    const salt2 = new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]);

    const encryptedKey1 = await cryptoData.encryptSecretKey(secret, salt1);
    const encryptedKey2 = await cryptoData.encryptSecretKey(secret, salt2);

    expect(encryptedKey1).not.toBe(encryptedKey2);
  });
});

describe('decryptSecretKey', () => {
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const secret = 'mySecretKey';
  const testData = new Uint8Array([1, 2, 3, 4, 5]);

  it('should decrypt the secret key correctly', async () => {
    const originalKey = await cryptoData.generateEncryptionSecretKey(secret, salt);
    const decryptedKey = await cryptoData.decryptSecretKey(secret, salt);
    expect(decryptedKey).not.toBeNull();
    if (decryptedKey) {
      expect(await crypto.subtle.exportKey('raw', decryptedKey)).toEqual(
        await crypto.subtle.exportKey('raw', originalKey)
      );
    }
  });

  it('should not decrypt the data if an incorrect secret is provided', async () => {
    const secret = 'mySecretKey';
    const incorrectSecret = 'wrongSecretKey';
    const originalKey = await cryptoData.generateEncryptionSecretKey(secret, salt);
    const decryptedKey = await cryptoData.decryptSecretKey(incorrectSecret, salt);

    expect(decryptedKey).not.toBeNull();
    if (decryptedKey && originalKey) {
      const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, originalKey, testData);
      await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, decryptedKey, encryptedData)).rejects.toThrow();
    }
  });

  it('should not decrypt the data if an incorrect salt is provided', async () => {
    const secret = 'mySecretKey';
    const incorrectSalt = new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]);
    const originalKey = await cryptoData.generateEncryptionSecretKey(secret, salt);
    const incorrectKey = await cryptoData.decryptSecretKey(secret, incorrectSalt);

    expect(incorrectKey).not.toBeNull();
    if (incorrectKey && originalKey) {
      const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, originalKey, testData);
      await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, incorrectKey, encryptedData)).rejects.toThrow();
    }
  });
});

describe('Generate key and encrypt jwt token', () => {
  it('should return original token jwtAccessTokenExample', async () => {
    const encryptedKey = await cryptoData.encryptKey();
    const decryptedKey = await cryptoData.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoData.encryptJWT(jwt, decryptedKey);
    const decryptedJWT = await cryptoData.decryptJWT(encryptedJWT, decryptedKey);

    expect(decryptedJWT).toEqual(jwt);
  });
});
