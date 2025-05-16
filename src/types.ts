// import {
//   Hasher,
//   kbHeader,
//   KBOptions,
//   kbPayload,
//   SaltGenerator,
//   Signer,
// } from "@sd-jwt/types";
// import { IJwtService } from "@sphereon/ssi-sdk-ext.jwt-service";
// import { X509CertificateChainValidationOpts } from "@sphereon/ssi-sdk-ext.x509-utils";
// import { contextHasPlugin } from "@sphereon/ssi-sdk.agent-config";
// import { ImDLMdoc } from "@sphereon/ssi-sdk.mdl-mdoc";
import {
  // HasherSync,
  JoseSignatureAlgorithm,
  // JsonWebKey,
  // SdJwtTypeMetadata,
} from "@sphereon/ssi-types";
export type EncryptedDisclosures = {
  ciphertext: string;
  iv: string;
  ephemeralPubKey: string;
  alg: string;
  enc: string;
};
