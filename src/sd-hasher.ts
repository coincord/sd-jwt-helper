import { pack } from "@sd-jwt/core";
import { Disclosure } from "@sd-jwt/utils";
import type {
  DisclosureFrame,
  Hasher,
  HasherAndAlg,
  SaltGenerator,
} from "@sd-jwt/types";
import * as u8a from "uint8arrays";
import { sha256 } from "@noble/hashes/sha2";
import { sha384, sha512 } from "@noble/hashes/sha2";
import type { SupportedEncodings } from "uint8arrays/to-string";
import { fromString } from "uint8arrays/from-string";
import type { EncryptedPayload } from "./encryption";
import { decryptDisclosures, encryptDisclosures } from "./encryption";

export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";
export type TDigestMethod = (
  input: string,
  encoding?: SupportedEncodings,
) => string;

const sha256DigestMethod = (
  input: string,
  encoding: SupportedEncodings = "base16",
): string => {
  return u8a.toString(sha256(u8a.fromString(input, "utf-8")), encoding);
};

const sha384DigestMethod = (
  input: string,
  encoding: SupportedEncodings = "base16",
): string => {
  return u8a.toString(sha384(u8a.fromString(input, "utf-8")), encoding);
};

const sha512DigestMethod = (
  input: string,
  encoding: SupportedEncodings = "base16",
): string => {
  return u8a.toString(sha512(u8a.fromString(input, "utf-8")), encoding);
};

export const digestMethodParams = (
  hashAlgorithm: HashAlgorithm,
): {
  hashAlgorithm: HashAlgorithm;
  digestMethod: TDigestMethod;
  hash: (data: Uint8Array) => Uint8Array;
} => {
  if (hashAlgorithm === "SHA-256") {
    return {
      hashAlgorithm: "SHA-256",
      digestMethod: sha256DigestMethod,
      hash: sha256,
    };
  } else if (hashAlgorithm === "SHA-384") {
    return {
      hashAlgorithm: "SHA-384",
      digestMethod: sha384DigestMethod,
      hash: sha384,
    };
  } else {
    return {
      hashAlgorithm: "SHA-512",
      digestMethod: sha512DigestMethod,
      hash: sha512,
    };
  }
};

export const defaultHasher = (
  data: string | ArrayBuffer,
  alg: string,
): Uint8Array => {
  return digestMethodParams(alg.includes("256") ? "SHA-256" : "SHA-512").hash(
    typeof data === "string" ? fromString(data, "utf-8") : new Uint8Array(data),
  );
};

interface IDisclosureFrame {
  _sd?: string[];
  _sd_decoy?: number;
  [x: string]: string[] | number | IDisclosureFrame | undefined;
}

export class SDPackHash {
  hasher: Hasher;
  alg: string;
  saltGen: SaltGenerator;

  constructor(
    salt_generator: SaltGenerator,
    hasher: HasherAndAlg = { hasher: defaultHasher, alg: "sha256" },
  ) {
    this.hasher = hasher.hasher;
    this.alg = hasher.alg;

    this.saltGen = salt_generator;
  }

  async packEncoding<T extends Record<string, unknown | boolean>>(
    claims: T,
    disclosuresFrame?: DisclosureFrame<T>,
  ): Promise<{
    packedClaims: Record<string, unknown> | Array<Record<string, unknown>>;
    disclosures: Disclosure<unknown>[];
    _hash_alg: string;
  }> {
    const { packedClaims, disclosures } = await pack(
      claims,
      // @ts-ignore OPTIMIZE: Resolve Type mismatch issues here
      disclosuresFrame,
      { hasher: this.hasher, alg: this.alg },
      this.saltGen,
    );

    return {
      _hash_alg: this.alg,
      packedClaims,
      // @ts-ignore
      disclosures,
    };
  }

  async generateEncryptedDisclosure(
    disclosures: Array<Disclosure>,
    recieverKey: string,
  ) {
    let encryptedDisclosures = await encryptDisclosures(
      disclosures,
      recieverKey,
    );
    return encryptedDisclosures;
  }

  async decryptDisclosure(
    encryptedPayload: EncryptedPayload,
    receiverEdPrivateKeyHex: string,
  ) {
    return await decryptDisclosures(encryptedPayload, receiverEdPrivateKeyHex);
  }
}
