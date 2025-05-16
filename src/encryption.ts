// Import only the necessary modules without duplicates
import { randomBytes } from "@noble/hashes/utils";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { base64ToBytes, bytesToBase64url } from "./utils/utils";

export type EncryptedPayload = {
  ciphertext: string;
  iv: string;
  ephemeralPubKey: string;
  alg: string;
  enc: string;
};

// Function to encrypt disclosures using X25519 key exchange
export async function encryptDisclosures(
  disclosures: any,
  receiverEdPublicKey: string,
) {
  // Generate ephemeral X25519 key pair for the sender
  const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

  // Convert receiver's Ed25519 public key to X25519 public key
  const receiverX25519PublicKey = convertEd25519PublicKeyToX25519(
    hexToBytes(receiverEdPublicKey),
  );

  // Calculate shared secret using X25519
  const sharedSecret = x25519.scalarMult(
    ephemeralPrivateKey,
    receiverX25519PublicKey,
  );

  // Derive encryption key using HKDF with SHA-256
  const encryptionKey = hkdf(
    sha256,
    sharedSecret,
    undefined,
    "sd-jwt-disclosure",
    32,
  );

  // Generate random IV for AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Import the encryption key into the Web Crypto API
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encryptionKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  // Encrypt the disclosures
  const data = new TextEncoder().encode(JSON.stringify(disclosures));
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    cryptoKey,
    data,
  );

  // Return the encrypted result with necessary metadata
  return {
    ciphertext: Buffer.from(encrypted).toString("base64"),
    iv: Buffer.from(iv).toString("base64"),
    ephemeralPubKey: bytesToBase64url(ephemeralPublicKey),
    alg: "X25519-AES-GCM",
    enc: "AES-GCM",
  };
}

export async function decryptDisclosures(
  encryptedPayload: EncryptedPayload,
  receiverEdPrivateKeyHex: string, // Hex string
) {
  // 1. Convert receiver's Ed25519 private key to X25519 private key
  const receiverX25519PrivateKey = convertEd25519PrivateKeyToX25519(
    hexToBytes(receiverEdPrivateKeyHex),
  );

  // 2. Decode ephemeral public key
  // const ephemeralPublicKey = Buffer.from(
  //   encryptedPayload.ephemeralPubKey,
  //   "base64",
  // );

  const ephemeralPublicKey = base64ToBytes(encryptedPayload.ephemeralPubKey);

  // 3. Compute shared secret
  const sharedSecret = x25519.scalarMult(
    receiverX25519PrivateKey,
    ephemeralPublicKey,
  );

  console.log(bytesToHex(sharedSecret));

  // 4. Derive encryption key via HKDF
  const encryptionKey = hkdf(
    sha256,
    sharedSecret,
    undefined,
    "sd-jwt-disclosure",
    32,
  );

  // 5. Import the derived key into Web Crypto
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encryptionKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  // 6. Decrypt the ciphertext
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(encryptedPayload.iv),
    },
    cryptoKey,
    base64ToBytes(encryptedPayload.ciphertext),
  );

  // 7. Decode the result
  return JSON.parse(new TextDecoder().decode(decrypted));
}

export function convertEd25519PublicKeyToX25519(
  publicKey: Uint8Array,
): Uint8Array {
  // FIXME: Once https://github.com/paulmillr/noble-curves/issues/31 gets released, this code can be simplified
  const Fp = ed25519.CURVE.Fp;
  const { y } = ed25519.ExtendedPoint.fromHex(publicKey);
  const _1n = BigInt(1);
  return Fp.toBytes(Fp.create((_1n + y) * Fp.inv(_1n - y)));
}

/**
 * Converts Ed25519 private keys to X25519
 * @param privateKey - The bytes of an Ed25519P private key
 *
 * @beta This API may change without a BREAKING CHANGE notice.
 */
export function convertEd25519PrivateKeyToX25519(
  privateKey: Uint8Array,
): Uint8Array {
  // FIXME: Once https://github.com/paulmillr/noble-curves/issues/31 gets released, this code can be simplified
  const hashed = ed25519.CURVE.hash(privateKey.subarray(0, 32));
  return (
    ed25519?.CURVE?.adjustScalarBytes?.(hashed)?.subarray(0, 32) ??
    new Uint8Array(0)
  );
}

// // Example function to convert Ed25519 keys to X25519 keys
// function convertKeys() {
//   // Ed25519 private key (32 bytes)
//   const edPrivateKey = ...; // from secure storage
//
//   // Convert Ed25519 private key to X25519 private key
//   const xPrivateKey = ed25519.utils.ed25519PrivateKeyToX25519(edPrivateKey);
//
//   // Get the Ed25519 public key from the private key
//   const edPublicKey = ed25519.getPublicKey(edPrivateKey);
//
//   // Convert Ed25519 public key to X25519 public key
//   const xPublicKey = ed25519.utils.edwardsToMontgomery(edPublicKey);
//
//   return { xPrivateKey, xPublicKey };
// }
//
// // Usage example:
// async function example() {
//   // Receiver's Ed25519 public key (from DID document or out-of-band)
//   const receiverEdPublicKey = ...;
//
//   // Data to encrypt (disclosures)
//   const disclosures = [...];
//
//   // Encrypt the disclosures
//   const encryptedData = await encryptDisclosures(disclosures, receiverEdPublicKey);
//
//   return encryptedData;
// }
