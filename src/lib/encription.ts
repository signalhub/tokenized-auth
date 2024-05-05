/**
 * Calculates SHA-256 hash of the input string
 * @param message - input string
 * @returns hash string
 */
const sha256 = async (message: string) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hash));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * Calculates SHA-256 hash of the input string
 * @param jwt - input string
 * @param storageKey - input string
 * @returns hash string
 */
const saveJWTHashToStorage = async (jwt: string, storageKey = "accessTokenHash") => {
  const jwtHash = await sha256(jwt);
  localStorage.setItem(storageKey, jwtHash);
};

/**
 * Verifies if the JWT hash stored in the storage is equal to the hash of the input JWT
 * @param jwt - input JWT
 * @param storageKey - key to store the hash in the storage
 * @returns boolean
 */
const verifyJWTFromStorage = async (jwt: string,  storageKey = "accessTokenHash") => {
  const storedJWTHash = localStorage.getItem(storageKey);
  if (storedJWTHash) {
    const jwtHash = await sha256(jwt);
    return jwtHash === storedJWTHash;
  }
  return false;
};

/**
 * Generates an encryption key
 * @returns CryptoKey
 */
const generateEncryptionKey = async (): Promise<CryptoKey> => {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

/**
 * Generates an encryption key and returns it as a base64 string
 * @returns base64 string
 */
const encryptKey = async (): Promise<string> => {
  const key = await generateEncryptionKey();
  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const exportedKeyBuffer = Buffer.from(exportedKey);
  return exportedKeyBuffer.toString('base64');
};

/**
 * Decrypts the input key
 * @param encryptedKey - input encrypted key
 * @returns decrypted key
 */
const decryptKey = async (encryptedKey: string): Promise<CryptoKey> => {
  const exportedKey = Buffer.from(encryptedKey, 'base64');
  return await crypto.subtle.importKey(
    'raw',
    exportedKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

/**
 * Encrypts the input JWT with the input key
 * @param jwt - input JWT
 * @param key - encryption key
 * @returns encrypted JWT
 */
const encryptJWT = async (jwt: string, key: CryptoKey): Promise<string> => {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(jwt)
  );
  const encryptedArray = Array.from(new Uint8Array(encryptedData));
  const encryptedJWT = encryptedArray.map(byte => String.fromCharCode(byte)).join('');
  const base64IV = Buffer.from(iv).toString('base64');
  const base64EncryptedJWT = Buffer.from(encryptedJWT, 'binary').toString('base64');
  return `${base64IV}.${base64EncryptedJWT}`;
};

/**
 * Decrypts the input JWT with the input key
 * @param encryptedJWT - input encrypted JWT
 * @param key - encryption key
 * @returns decrypted JWT
 */
const decryptJWT = async (encryptedJWT: string, key: CryptoKey): Promise<string> => {
  const parts = encryptedJWT.split('.');
  const iv = new Uint8Array(Buffer.from(parts[0], 'base64'));
  const encryptedText = Buffer.from(parts[1], 'base64').toString('binary');
  const encryptedData = new Uint8Array(encryptedText.split('').map(char => char.charCodeAt(0)));
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedData
  );
  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
};


/**
 * Generates an encryption key using a secret parameter
 * @param secret - secret parameter used for key generation
 * @param salt - salt used for key generation
 * @returns CryptoKey
 */
const generateEncryptionSecretKey = async (secret: string, salt: Uint8Array): Promise<CryptoKey> => {
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

/**
 * Generates an encryption key using a secret parameter and returns it as a base64 string
 * @param secret - secret parameter used for key generation
 * @param salt - salt used for key generation
 * @returns base64 string
 */
const encryptSecretKey = async (secret: string, salt: Uint8Array): Promise<string> => {
  const key = await generateEncryptionSecretKey(secret, salt);
  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const exportedKeyBuffer = Buffer.from(exportedKey);
  return exportedKeyBuffer.toString('base64');
};

 /**
 * Decrypts the input key using a secret parameter and verifies the decryption
 * @param secret - secret parameter used for key generation
 * @param salt - salt used for key generation
 * @returns decrypted key if successful, null otherwise
 */
 const decryptSecretKey = async (secret: string, salt: Uint8Array): Promise<CryptoKey | null> => {
   const secretKey = await crypto.subtle.importKey(
     'raw',
     new TextEncoder().encode(secret),
     { name: 'PBKDF2' },
     false,
     ['deriveKey']
   );

   const decryptedKey = await crypto.subtle.deriveKey(
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

   const decryptedKeyBuffer = await crypto.subtle.exportKey('raw', decryptedKey);
   return decryptedKeyBuffer ? decryptedKey : null;
 };

export const cryptoData = {
  generateEncryptionKey,
  generateEncryptionSecretKey,
  encryptKey,
  decryptKey,
  encryptJWT,
  decryptJWT,
  encryptSecretKey,
  decryptSecretKey,
};
