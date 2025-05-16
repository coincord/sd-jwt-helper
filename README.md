# @coincord/sd-jwt-helper

Helper utilities for SD-JWT (Selective Disclosure JSON Web Token) operations, designed to simplify working with verifiable credentials and self-sovereign identity (SSI) applications.

## Features

- 🔒 **Encrypted Disclosures**: Support for encrypted selective disclosure claims
- 🧩 **Selective Disclosure**: Easily define which parts of your JWT payload can be selectively disclosed
- 🛠️ **Helper Functions**: Utilities for encoding, decoding, and packing SD-JWTs
- 📦 **TypeScript Support**: Full TypeScript type definitions for better development experience
- 🔄 **SD-JWT Standards Compliant**: Built on top of the SD-JWT specification and libraries

## Installation

```bash
# Using npm
npm install @coincord/sd-jwt-helper

# Using yarn
yarn add @coincord/sd-jwt-helper

# Using pnpm
pnpm add @coincord/sd-jwt-helper
```

## Usage

### Basic Usage

```typescript
import { SDJwtEnc, pack, SDPackHash } from "@coincord/sd-jwt-helper";
import { Jwt } from "@sd-jwt/core";

// Create a JWT
const jwt = new Jwt({
  header: { alg: "ES256" },
  payload: {
    sub: "1234567890",
    name: "John Doe",
    email: "john.doe@example.com",
    age: 25,
  },
});

// Define which claims should be selectively disclosable
const disclosureFrame = {
  _sd: ["email", "age"], // These claims will be selectively disclosable
};

// Create a hasher
const hasher = new SDPackHash();

// Generate random salts
const saltGenerator = async (length: number) => {
  // In a real application, use a secure random generator
  return "randomsalt";
};

// Pack the claims with selective disclosure
const { packedClaims, disclosures } = await pack(
  jwt.payload,
  disclosureFrame,
  hasher,
  saltGenerator,
);

// Update the JWT payload with the packed claims
jwt.payload = packedClaims;

// Create an encrypted SD-JWT
const sdJwt = new SDJwtEnc({
  jwt,
  disclosures,
});

// Encode the SD-JWT
const encodedSdJwt = sdJwt.encodeSDJwtEnc();
```

### Decoding an Encrypted Disclosure SD-JWT

```typescript
import { SDJwtEnc } from "@coincord/sd-jwt-helper";

// Decode an encoded SD-JWT
const decodedSdJwt = await SDJwtEnc.fromEncodeEnc(encodedSdJwt);

// Access the JWT and disclosures
const { jwt, encrypted_disclosures } = decodedSdJwt;
```

## API Reference

### Classes

#### `SDJwtEnc<Header, Payload, KBHeader, KBPayload>`

The main class for working with SD-JWTs that include encrypted disclosures.

**Constructor:**

```typescript
constructor(data?: SDJwtData<Header, Payload, KBHeader, KBPayload>)
```

**Static Methods:**

- `decodeSDJwtEnc<Header, Payload, KBHeader, KBPayload>(sdjwt: SDJWTCompact)`: Decodes an SD-JWT compact string
- `fromEncodeEnc<Header, Payload, KBHeader, KBPayload>(encodedSdJwt: SDJWTCompact)`: Creates an SDJwtEnc instance from an SD-JWT compact string

**Instance Methods:**

- `encodeSDJwtEnc()`: Encodes the SD-JWT to a compact string format

#### `SDPackHash`

A hasher implementation for SD-JWT operations.

### Functions

#### `pack<T>(claims: T, disclosureFrame: DisclosureFrame<T> | undefined, hash: HasherAndAlg, saltGenerator: SaltGenerator)`

Packs claims according to a disclosure frame to create selectively disclosable claims.

**Parameters:**

- `claims`: The original claims to be packed
- `disclosureFrame`: Frame defining which claims should be selectively disclosable
- `hash`: Hasher and algorithm to use for creating digests
- `saltGenerator`: Function to generate salts for disclosures

**Returns:**

- `packedClaims`: The packed claims with digests replacing disclosable claims
- `disclosures`: Array of disclosure objects

#### `listKeys(obj: Record<string, unknown>, prefix = "")`

Lists all keys in an object, including nested keys with dot notation.

## License

MIT © [Coincord](https://coincord.io)
