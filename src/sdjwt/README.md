# SD-JWT Validation

This module provides strict decoding and validation for SD-JWT and VC+SD-JWT tokens.

## Goals

- Validate SD-JWT token structure and schema with clear failure reasons.
- Support optional signature, expiration, and disclosure-hash verification.
- Keep a minimal public API for consumers while encapsulating parsing internals.

## Public API

```ts
import {
  decodeSDJWT,
  isSDJWTExpired,
  type ValidationOptions,
  type DecodeResult,
  type SDJWT,
  type VCSDJWT,
} from "@abgov/verifiable-credentials";
```

Main entry points:

- `decodeSDJWT(token, options): Promise<DecodeResult<T>>`
- `isSDJWTExpired(token): boolean`

Core options:

- `verifySignature`: enable JWT signature verification.
- `checkExpiration`: enforce `exp` claim checks.
- `validateDisclosureHashes`: verify disclosure digests against `_sd`.
- `signingKeyResolver`: resolve verification keys from `iss`, `kid`, and `alg`.

## Behavior Summary

### Decode Flow

1. Parse SD-JWT compact+disclosures format (`jwt~disclosure~...`).
2. Validate JWT compact structure and supported `typ`/`alg` values.
3. Decode payload (including DEF-compressed payload support).
4. Optionally verify JWT signature via `signingKeyResolver`.
5. Parse disclosures and merge into disclosed-claims map.
6. Optionally validate disclosure hashes against `_sd` values.
7. Optionally enforce expiration (`exp`) checks.
8. Validate payload against SD-JWT or VC+SD-JWT schema.

### Supported Token Types

- `sd-jwt`
- `vc+sd-jwt`

### Supported Signature Algorithms

- `RS256`, `RS384`, `RS512`
- `ES256`, `ES384`, `ES512`

### Compression Handling

- Supports JWT payload compression (`zip: DEF`).
- Signature verification for compressed payloads uses compact JWS verification.

## Validation Model

Validation is performed in this order:

1. JWT format checks.
2. Header checks (`typ`, `alg`, optional compression metadata).
3. Payload decode/decompression.
4. Optional cryptographic signature validation.
5. Disclosure parsing and optional hash validation.
6. Optional expiration validation.
7. JSON schema validation (SD-JWT or VC+SD-JWT).

### CKAPP Validation

Decodes and verifies a CKAPP (Credential Key Attestation Proof) presentation.

CKAPP is a binary proof format (182 bytes total) that wraps an SD-JWT credential with:

- **Central attestation** (106 bytes): `version` + `keyId` + holder compressed public key + `iat0` + central signature
- **Holder proof** (76 bytes): `iat1` + 8-byte nonce + holder signature

**Format:** `{SD-JWT}~{base64(CKAPP)}`

### Decoding Process

1. Parse CKAPP binary structure (182 bytes)
2. Verify central (issuer) signature using `proofSigningKeyResolver`
3. Verify holder signature using holder public key from attestation
4. Validate proof timestamp (must be within `proofMaxAgeSeconds`)

### `verifyCKAPPProofSignature` — Verify CKAPP Proof Signatures

Verifies both central (issuer) and holder (user) signatures in a CKAPP proof.

- **Central signature (`sigC`):** Resolves the wallet's central signing public key via `proofSigningKeyResolver` and verifies signature over: `ATSTv1 || version || central_kid || holder_pub || iat0`
- **Holder signature (`sigU`):** Uses the holder's compressed public key from the attestation and verifies signature over: `PRESv1 || VC || 0x7E || Attestation || (iat1 || nonce)`

## Error Model

`decodeSDJWT` returns a `DecodeResult` envelope:

- `valid: true` with `data` and optional `disclosures`.
- `valid: false` with a descriptive `error` string, and in some cases (e.g., expired tokens) partial `data` may also be present.

Common failure categories include:

- invalid JWT format/header
- unsupported token type or algorithm
- signature/key-resolution failures
- decompression failures
- disclosure hash mismatches
- expiration failures
- schema validation failures

## Example: Basic Decode

```ts
const result = await decodeSDJWT(token);

if (!result.valid) {
  console.error(result.error);
} else {
  console.log(result.data);
  console.log(result.disclosures);
}
```

## Example: Full Validation

```ts
const result = await decodeSDJWT(token, {
  verifySignature: true,
  checkExpiration: true,
  validateDisclosureHashes: true,
  signingKeyResolver: async (iss, kid, alg) => {
    const jwks = await fetch(`${iss}/.well-known/jwks.json`).then((r) =>
      r.json(),
    );
    const key = jwks.keys.find(
      (k: { kid?: string; alg?: string }) =>
        k.kid === kid && (!alg || !k.alg || k.alg === alg),
    );

    if (!key) {
      throw new Error(`Key ${kid} not found for issuer ${iss}`);
    }

    return await crypto.subtle.importKey(
      "jwk",
      key,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  },
});
```

## JSON Schemas

- `schemas/sd-jwt-v1.json`
- `schemas/vc+sd-jwt-v1.json`

## Internal Modules

- `decode.ts`: decode and validation pipeline.
- `schema-validator.ts`: schema selection and validation.
- `utilities.ts`: token decoding, decompression, and hash helpers.
- `types.ts`: public SD-JWT type definitions.

## Test Files

- `decode.test.ts`
