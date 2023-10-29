const PUBLIC_KEY_STRING = import.meta.env.VITE_MA_PUBLIC_KEY_STRING;
const PUBLIC_KEY_VERSION = import.meta.env.VITE_MA_PUBLIC_KEY_VERSION;

async function importRSAKey(): Promise<CryptoKey> {
  const key = await window.crypto.subtle.importKey(
    'spki',
    new Uint8Array(
      atob(PUBLIC_KEY_STRING)
        .split('')
        .map(c => c.charCodeAt(0))
    ),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'wrapKey']
  );
  return key;
}

async function generateAESKey(): Promise<CryptoKey> {
  const key = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 128,
    },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function encryptRSA(
  key: CryptoKey,
  plainText: string
): Promise<ArrayBuffer> {
  const encoded = new TextEncoder().encode(plainText);
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    key,
    encoded
  );
  return encrypted;
}

async function encryptAES(
  key: CryptoKey,
  plainText: string
): Promise<ArrayBuffer> {
  const encoded = new TextEncoder().encode(plainText);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encoded
  );
  return encrypted;
}

async function wrapSecret(
  key: CryptoKey,
  secret: CryptoKey
): Promise<ArrayBuffer> {
  const wrapped = await window.crypto.subtle.wrapKey('raw', secret, key, {
    name: 'RSA-OAEP',
  });
  return wrapped;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export type SignedPayload = {
  disneyInternalUse01: string;
  disneyInternalUse02: string;
  disneyInternalUse03: string;
};

export async function generateSignedPayload(
  payload: string
): Promise<SignedPayload> {
  // Generate keys
  const publicKey = await importRSAKey();
  const aesKey = await generateAESKey();

  // Wrap the AES key with the RSA public key
  const wrappedKey = await wrapSecret(publicKey, aesKey);

  // Encrypt the payload with the AES key
  const encryptedPayload = await encryptAES(aesKey, payload);

  // Base64 encode the wrapped AES key
  const encodedKey = arrayBufferToBase64(wrappedKey);

  // Base64 encode the encrypted payload
  const encodedPayload = arrayBufferToBase64(encryptedPayload);

  return {
    disneyInternalUse01: encodedPayload,
    disneyInternalUse02: PUBLIC_KEY_VERSION,
    disneyInternalUse03: encodedKey,
  };
}
