import { createDecoy } from "@sd-jwt/core";
import { SDJWTException, Disclosure } from "@sd-jwt/utils";
import { Jwt } from "@sd-jwt/core";
import { KBJwt } from "@sd-jwt/core";
import {
  type DisclosureFrame,
  // type Hasher,
  type HasherAndAlg,
  // type PresentationFrame,
  type SDJWTCompact,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
  type SaltGenerator,
  type kbHeader,
  type kbPayload,
} from "@sd-jwt/types";
import type { EncryptedDisclosures } from "./types";
import { EncDisclosure } from "./utils/enc-disclosure";

export type SDJwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> = {
  jwt?: Jwt<Header, Payload>;
  disclosures?: EncryptedDisclosures;
  kbJwt?: KBJwt<KBHeader, KBPayload>;
};

export class SDJwtEnc<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> {
  public jwt?: Jwt<Header, Payload>;
  public encrypted_disclosures?: EncDisclosure;
  public kbJwt?: KBJwt<KBHeader, KBPayload>;

  constructor(data?: SDJwtData<Header, Payload, KBHeader, KBPayload>) {
    this.jwt = data?.jwt;
    if (data?.disclosures) {
      this.encrypted_disclosures = new EncDisclosure(data?.disclosures);
    }
    this.kbJwt = data?.kbJwt;
  }

  public static async decodeSDJwtEnc<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: SDJWTCompact,
  ): Promise<{
    jwt: Jwt<Header, Payload>;
    encrypted_disclosures?: EncDisclosure;
    kbJwt?: KBJwt<KBHeader, KBPayload>;
  }> {
    const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
    const jwt = Jwt.fromEncode<Header, Payload>(<string>encodedJwt);

    if (!jwt.payload) {
      throw new Error("Payload is undefined on the JWT. Invalid state reached");
    }

    if (encodedDisclosures.length === 0) {
      return {
        jwt,
        encrypted_disclosures: undefined,
      };
    }

    const disclosures = await EncDisclosure.fromEncodeEnc(
      <string>encodedDisclosures[0],
    );

    return {
      jwt,
      encrypted_disclosures: disclosures,
    };
  }

  public static async fromEncodeEnc<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(encodedSdJwt: SDJWTCompact): Promise<SDJwtEnc<Header, Payload>> {
    const { jwt, encrypted_disclosures, kbJwt } = await SDJwtEnc.decodeSDJwtEnc<
      Header,
      Payload,
      KBHeader,
      KBPayload
    >(encodedSdJwt);

    return new SDJwtEnc<Header, Payload, KBHeader, KBPayload>({
      jwt,
      disclosures: encrypted_disclosures,
      kbJwt,
    });
  }

  public encodeSDJwtEnc(): SDJWTCompact {
    const data: string[] = [];

    if (!this.jwt) {
      throw new SDJWTException("Invalid sd-jwt: jwt is missing");
    }

    const encodedJwt = this.jwt.encodeJwt();
    data.push(encodedJwt);

    if (this.encrypted_disclosures) {
      data.push(this.encrypted_disclosures.encodeEnc());
    }

    data.push(this.kbJwt ? this.kbJwt.encodeJwt() : "");
    return data.join(SD_SEPARATOR);
  }
}

export const listKeys = (obj: Record<string, unknown>, prefix = "") => {
  const keys: string[] = [];
  for (const key in obj) {
    if (obj[key] === undefined) continue;
    const newKey = prefix ? `${prefix}.${key}` : key;
    keys.push(newKey);

    if (obj[key] && typeof obj[key] === "object" && obj[key] !== null) {
      keys.push(...listKeys(obj[key] as Record<string, unknown>, newKey));
    }
  }
  return keys;
};

export const pack = async <T extends Record<string, unknown>>(
  claims: T,
  disclosureFrame: DisclosureFrame<T> | undefined,
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<{
  packedClaims: Record<string, unknown> | Array<Record<string, unknown>>;
  disclosures: Array<Disclosure>;
}> => {
  if (!disclosureFrame) {
    return {
      packedClaims: claims,
      disclosures: [],
    };
  }

  const sd = disclosureFrame[SD_DIGEST] ?? [];
  const decoyCount = disclosureFrame[SD_DECOY] ?? 0;

  if (Array.isArray(claims)) {
    const packedClaims: Array<Record<typeof SD_LIST_KEY, string>> = [];
    const disclosures: Array<Disclosure> = [];
    const recursivePackedClaims: Record<number, unknown> = {};

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const idx = Number.parseInt(key);
        const packed = await pack(
          claims[idx],
          disclosureFrame[idx],
          hash,
          saltGenerator,
        );
        recursivePackedClaims[idx] = packed.packedClaims;
        disclosures.push(...packed.disclosures);
      }
    }

    for (let i = 0; i < claims.length; i++) {
      const claim = recursivePackedClaims[i]
        ? recursivePackedClaims[i]
        : claims[i];
      // @ts-ignore
      if (sd.includes(i)) {
        const salt = await saltGenerator(16);
        const disclosure = new Disclosure([salt, claim]);
        const digest = await disclosure.digest(hash);
        packedClaims.push({ [SD_LIST_KEY]: digest });
        disclosures.push(disclosure);
      } else {
        packedClaims.push(claim);
      }
    }
    for (let j = 0; j < decoyCount; j++) {
      const decoyDigest = await createDecoy(hash, saltGenerator);
      packedClaims.push({ [SD_LIST_KEY]: decoyDigest });
    }
    return { packedClaims, disclosures };
  }

  const packedClaims: Record<string, unknown> = {};
  const disclosures: Array<Disclosure> = [];
  const recursivePackedClaims: Record<string, unknown> = {};

  for (const key in disclosureFrame) {
    if (key !== SD_DIGEST) {
      const packed = await pack(
        // @ts-ignore
        claims[key],
        disclosureFrame[key],
        hash,
        saltGenerator,
      );
      recursivePackedClaims[key] = packed.packedClaims;
      disclosures.push(...packed.disclosures);
    }
  }

  const _sd: string[] = [];

  for (const key in claims) {
    const claim = recursivePackedClaims[key]
      ? recursivePackedClaims[key]
      : claims[key];
    // @ts-ignore
    if (sd.includes(key)) {
      const salt = await saltGenerator(16);
      const disclosure = new Disclosure([salt, key, claim]);
      const digest = await disclosure.digest(hash);

      _sd.push(digest);
      disclosures.push(disclosure);
    } else {
      packedClaims[key] = claim;
    }
  }

  for (let j = 0; j < decoyCount; j++) {
    const decoyDigest = await createDecoy(hash, saltGenerator);
    _sd.push(decoyDigest);
  }

  if (_sd.length > 0) {
    packedClaims[SD_DIGEST] = _sd.sort();
  }
  return { packedClaims, disclosures };
};
