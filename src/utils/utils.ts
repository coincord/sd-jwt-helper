import * as u8a from "uint8arrays";

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, "base64url");
}

export function base64ToBytes(s: string): Uint8Array {
  const inputBase64Url = s
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return u8a.fromString(inputBase64Url, "base64url");
}

export function bytesToBase64(b: Uint8Array): string {
  return u8a.toString(b, "base64pad");
}

export function base58ToBytes(s: string): Uint8Array {
  return u8a.fromString(s, "base58btc");
}

export function bytesToBase58(b: Uint8Array): string {
  return u8a.toString(b, "base58btc");
}
