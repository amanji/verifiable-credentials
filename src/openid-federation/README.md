# OpenID Federation Discovery

This module provides strict, schema-validated discovery for OpenID Federation 1.0 entities.

## Goals

- Validate federation artifacts with JSON Schemas before trust processing.
- Support local trust-chain construction (`federation_fetch_endpoint`).

## Public API

```ts
import {
  discoverFederationEntity,
  type FederationDiscoveryRequest,
  type FederationDiscoveryOptions,
} from "@abgov/verifiable-credentials";
```

Main entry point:

- `discoverFederationEntity(request, options): Promise<FederationDiscoveryResult>`

Core request fields:

- `entityId`: subject entity identifier (must be HTTPS URI).
- `trustAnchors`: trusted anchor entity identifiers.

Core options:

- `fetcher`: optional custom `fetch` implementation.
- `maxAuthorityHints`, `maxChainDepth`, `clockSkewSeconds`, `now`.

## Behavior Summary

### Local Mode

1. Fetch subject entity configuration (`/.well-known/openid-federation`).
2. Walk `authority_hints` upwards.
3. Fetch subordinate statements from each superior `federation_fetch_endpoint`.
4. Build candidate chains and verify signatures/continuity.
5. Return metadata from the discovered subject entity configuration.

## Validation Model

Strict validation is applied in this order:

1. JOSE/JWT header checks (`typ`, `alg`, `kid`).
2. Schema validation of decoded payloads.
3. Temporal checks (`iat`, `exp`) with configured skew.
4. Signature validation using chained JWKS.

## Error Model

Discovery returns a typed error envelope when `valid` is `false`:

- `InvalidInput`
- `NetworkError`
- `InvalidJwtType`
- `SchemaValidationFailed`
- `TrustChainInvalid`
- `Unsupported`

Notes:

- Codes are assigned by message classification in `discoverFederationEntity`.
- Some low-level failures may map to a broader code than expected when message keywords overlap.

## Example: Local Discovery

```ts
const result = await discoverFederationEntity(
  {
    entityId: "https://wallet.example.org",
    trustAnchors: ["https://ta.example.org"],
  },
  {},
);

if (!result.valid) {
  console.error(result.error?.code, result.error?.message);
} else {
  console.log(result.data.metadata);
}
```

## Internal Modules

- `discovery.ts`: orchestration and endpoint interactions.
- `verification.ts`: JWT parsing and trust-chain signature checks.
- `schema-validator.ts`: schema compilation and runtime validation helpers.
- `test-utils.ts`: reusable local-chain fixtures and fetch mocks for unit tests.

## Test Files

- `discovery.test.ts`
- `verification.test.ts`
