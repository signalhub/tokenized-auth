import { cryptoAuthUtils } from '@tokenized-auth/source';
import { describe } from 'vitest';

describe('generateEncryptionKey', () => {
  it('should return a text key', async () => {
    // as util method, should not be used in production
    const key = await cryptoAuthUtils.generateEncryptionKey();
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
    const key = await cryptoAuthUtils.encryptKey();
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
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);

    expect(decryptedKey).toBeInstanceOf(CryptoKey);
    expect(decryptedKey.type).toBe('secret');
    expect(decryptedKey.extractable).toBe(true);
    expect(decryptedKey.algorithm).toEqual({ name: 'AES-GCM', length: 256 });
    expect(decryptedKey.usages).toEqual(['encrypt', 'decrypt']);
  });

  it('should throw an error for invalid encrypted key', async () => {
    const invalidEncryptedKey = "invalid_key";

    await expect(cryptoAuthUtils.decryptKey(invalidEncryptedKey)).rejects.toThrow();
  });
});

describe('encryptJWT', () => {
  it('should encrypt and decrypt a JWT successfully', async () => {
    const encryptedKey = "FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(jwt, decryptedKey);
    const decryptedJWT = await cryptoAuthUtils.decryptJWT(encryptedJWT, decryptedKey);

    expect(decryptedJWT).toEqual(jwt);
  });
});

describe('decryptJWT', () => {
  it('should decrypt the encrypted JWT and return the original JWT', async () => {
    const encryptedKey = "FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const originalJWT = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(originalJWT, decryptedKey);
    const decryptedJWT = await cryptoAuthUtils.decryptJWT(encryptedJWT, decryptedKey);

    expect(decryptedJWT).toEqual(originalJWT);
  });
});

describe('Generate key and encrypt jwt token', () => {
  it('should return original token jwtAccessTokenExample', async () => {
    const encryptedKey = await cryptoAuthUtils.encryptKey();
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(jwt, decryptedKey);
    const decryptedJWT = await cryptoAuthUtils.decryptJWT(encryptedJWT, decryptedKey);

    expect(decryptedJWT).toEqual(jwt);
  });
});
