# @abgov/verifiable-credentials

Verifiable credential helper library for Alberta Digital Wallet.

## What This Package Provides

- SD-JWT decoding and validation utilities.
- OpenID Federation 1.0 entity discovery with strict schema validation.
- JSON schemas copied into `dist` for runtime validation and external use.

## Installation

```bash
npm install @abgov/verifiable-credentials
# or
yarn add @abgov/verifiable-credentials
```

## Public APIs

```ts
import {
  decodeSDJWT,
  isSDJWTExpired,
  discoverFederationEntity,
  resolveAlbertaWallet,
} from "@abgov/verifiable-credentials";
```

## Alberta Wallet

### Resolve Issuer + Display Template

```ts
import { resolveAlbertaWallet } from "@abgov/verifiable-credentials";

const resolved = resolveAlbertaWallet({
  ec,
  sdjwt,
});

console.log(resolved.albertaCredentialIssuer);
console.log(resolved.credentialConfiguration);
console.log(resolved.walletCardDisplayTemplate);
```

Resolution behavior:

- Detects Alberta issuer entity type from `ec.metadata` using JSON schema validation.
- Matches config by issuer: `sdjwt.iss === credential_issuer`.
- Matches config by type for `VCSDJWT` using `vct`.
- Matches config by type for `SDJWT` using `type`.

## SD-JWT

### Quick Example

```ts
import { decodeSDJWT } from "@abgov/verifiable-credentials";

const result = await decodeSDJWT(sdJwtToken);

if (result.valid) {
  console.log(result.data);
  console.log(result.disclosures);
} else {
  console.error(result.error);
}
```

### Validation Options

```ts
import type { ValidationOptions } from "@abgov/verifiable-credentials";

const options: ValidationOptions = {
  verifySignature: true,
  checkExpiration: true,
  validateDisclosureHashes: true,
  signingKeyResolver: async (iss, kid, alg) => {
    // Provide a public key for signature validation.
    throw new Error("implement key resolution");
  },
};
```

### Supported JWT Types

- `sd-jwt`
- `vc+sd-jwt`

### Supported Signature Algorithms

- RSA: `RS256`, `RS384`, `RS512`
- ECDSA: `ES256`, `ES384`, `ES512`

### SD-JWT Docs

- `src/sdjwt/README.md`

## OpenID Federation Discovery

### Quick Example

```ts
import { discoverFederationEntity } from "@abgov/verifiable-credentials";

const result = await discoverFederationEntity(
  {
    entityId: "https://wallet.example.org",
    trustAnchors: ["https://ta.example.org"],
  },
  {},
);

if (result.valid) {
  console.log(result.data?.metadata);
} else {
  console.error(result.error?.code, result.error?.message);
}
```

The discovery result returns metadata from the subject entity configuration and a validated trust chain.

Discovery errors are returned as typed codes (`InvalidInput`, `NetworkError`, `InvalidJwtType`, `SchemaValidationFailed`, `TrustChainInvalid`, `Unsupported`) via `result.error?.code`.

### Discovery Modes

- `local`: trust-chain construction via `federation_fetch_endpoint`.

### Federation Docs

- `src/openid-federation/README.md`

## JSON Schemas

Schema files are copied into the package build output:

- `dist/sdjwt/schemas/sd-jwt-v1.json`
- `dist/sdjwt/schemas/vc+sd-jwt-v1.json`
- `dist/openid-federation/schemas/entity-statement-v1.json`
- `dist/openid-federation/schemas/endpoint-error-v1.json`
- `dist/alberta-wallet/schemas/card-display-v1.json`
- `dist/alberta-wallet/schemas/alberta-credential-issuer-v1.json`

## Development

### Setup

```bash
corepack enable
yarn install

# Activate conventional commit template
git config commit.template .gitmessage
```

### Build

```bash
yarn build
```

Build steps:

1. Clean `dist`.
2. Compile TypeScript (ESM) and declarations.
3. Copy schema files to `dist/sdjwt/schemas`, `dist/openid-federation/schemas`, and `dist/alberta-wallet/schemas`.

### Test

```bash
yarn test
yarn test:watch
yarn test:coverage
```

### Lint

```bash
yarn lint
yarn lint:fix
```

### Format

Formatting is enforced with Prettier (config in `.prettierrc`) and is also surfaced through ESLint via `eslint-plugin-prettier`.

```bash
yarn format
yarn format:check
```

### Pack

```bash
yarn pack
```

## Publishing

Releases are managed by [release-please](https://github.com/googleapis/release-please).

1. Merge PR(s) with [conventional commit](https://www.conventionalcommits.org/) PR titles to `main`.
2. release-please opens a **Release PR** with the next version and CHANGELOG.
3. Merge the Release PR when ready to cut a release.
4. The publish workflow fires automatically and publishes to [registry.npmjs.org](https://registry.npmjs.org).

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full details.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT License. See [LICENSE](./LICENSE) for details.
