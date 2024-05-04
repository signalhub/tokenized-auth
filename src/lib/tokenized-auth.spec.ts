import { cryptoAuthUtils } from '@tokenized-auth/source';
import { describe } from 'vitest';

describe('generateEncryptionKey', () => {
  it('should return a text key', async () => {
    // as util method, should not be used in production
    const key = await cryptoAuthUtils.generateEncryptionKey();
    console.log(key);
  });
});

describe('encryptKey', () => {
  it('should return a text key', async () => {
    const key = await cryptoAuthUtils.encryptKey();
    // should save key to .env
    console.log({ key });
  });
});

describe('decryptKey', () => {
  it('should return a text key', async () => {
    // get key from .env
    const encryptedKey ="FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    console.log({ decryptedKey });
  });
});

describe('encryptJWT', () => {
  it('should return a text key', async () => {
    const encryptedKey ="FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(jwt, decryptedKey);
    console.log({ encryptedJWT });
  });
});

describe ('decryptJWT', () => {
  it('should return jwtAccessTokenExample', async () => {
    const encryptedKey ="FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(jwt, decryptedKey);
    const decryptedJWT = await cryptoAuthUtils.decryptJWT(encryptedJWT, decryptedKey);
    console.log({ decryptedJWT });
  });
});

describe('Generate key and encrypt jwt token', () => {
  it('should return a text key', async () => {
    const key = await cryptoAuthUtils.encryptKey();
    // should save key to .env
    console.log({ key });
  });

  it('should return a text key', async () => {
    const encryptedKey ="FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(jwt, decryptedKey);
    console.log({ encryptedJWT });
  });

  it('should return jwtAccessTokenExample', async () => {
    const encryptedKey ="FSPPSUi+tFZ68sFvW7e1OPM09J4XlqCnJDUTefXukR8=";
    const decryptedKey = await cryptoAuthUtils.decryptKey(encryptedKey);
    const jwt = 'jwtAccessTokenExample';
    const encryptedJWT = await cryptoAuthUtils.encryptJWT(jwt, decryptedKey);
    const decryptedJWT = await cryptoAuthUtils.decryptJWT(encryptedJWT, decryptedKey);
    console.log({ decryptedJWT });
  });
});

