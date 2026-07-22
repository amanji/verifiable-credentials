/**
 * SD-JWT Decoder
 * Decodes and validates JWT-based tokens with optional selective disclosure support
 * Supports SD-JWT (RFC-9901) and VC+SD-JWT formats
 */

import * as jose from 'jose';
import { SDJWT } from './types';
import { validateSDJWTAgainstSchema, validateVCSDJWTAgainstSchema } from './schema-validator';
import { computeHash, decompressString, getCurrentUnixTime } from './utilities';
import { base64urlToString, uint8ArrayToBase64url } from '../shared';
import { decodeCKAPP, decodeSecureQr } from './proof';
import {
  PresentationVerificationStatus,
  SecureQRProofValidationOptions,
  CKAPPProofValidationOptions,
  ProofTypeEnum,
} from './types';

export interface DecodeResult<T extends SDJWT = SDJWT> {
  valid: boolean;
  data?: T;
  disclosures?: Record<string, unknown>;
  error?: string;
  rawData?: string;
  rawDisclosures?: Record<string, unknown>;
  status?: PresentationVerificationStatus;
  proofIssuedAt?: Date;
}

/**
 * Key resolver function for dynamic public key lookup
 *
 * Resolves the public key to use for signature verification based on the token's
 * issuer (iss claim) and optional key ID (kid header parameter).
 *
 * @param iss - The issuer URI from the token's iss claim
 * @param kid - The key ID from the JWT header's kid parameter (optional)
 * @param alg - The signature algorithm from the JWT header's alg parameter (optional)
 * @returns Promise resolving to the public key (CryptoKey or Uint8Array) to use for verification
 * @throws {Error} If the key cannot be found or resolved
 *
 * @remarks
 * - Called during signature verification when no explicit publicKey is provided
 * - Should fetch from JWKS endpoint, key server, or local cache
 * - Can use both iss and kid for precise key identification
 * - Implementation should handle caching to avoid repeated lookups
 *
 * @example
 * ```typescript
 * const keyResolver: KeyResolver = async (iss, kid) => {
 *   const keySet = await fetch(`${iss}/.well-known/jwks.json`).then(r => r.json());
 *   const key = keySet.keys.find(k => k.kid === kid);
 *   if (!key) throw new Error(`Key ${kid} not found for issuer ${iss}`);
 *   return await crypto.subtle.importKey('jwk', key, ...);
 * };
 * ```
 */
export type KeyResolver = (
  iss: string,
  kid?: string,
  alg?: string
) => Promise<CryptoKey | Uint8Array>;

type ProofValidationOptions = CKAPPProofValidationOptions | SecureQRProofValidationOptions;

/**
 * Options for SD-JWT validation and decoding.
 *
 * The signingKeyResolver function is called to dynamically resolve public keys
 * based on token issuer (iss), key ID (kid), and optional algorithm (alg).
 *
 * @interface ValidationOptions
 * @property {boolean} [verifySignature=true] - Whether to verify the JWT signature
 * @property {boolean} [checkExpiration=true] - Whether to check token expiration
 * @property {boolean} [validateDisclosureHashes=true] - Whether to validate selective disclosure hashes
 * @property {KeyResolver} [signingKeyResolver] - Function to dynamically resolve public signing keys based on iss, kid, and alg from the token
 *
 * @example
 * ```typescript
 * // Using key resolution with iss, kid, and alg
 * const options: ValidationOptions = {
 *   verifySignature: true,
 *   signingKeyResolver: async (iss, kid, alg) => {
 *     const keySet = await fetch(`${iss}/.well-known/jwks.json`).then(r => r.json());
 *     const key = keySet.keys.find(k => k.kid === kid && (!alg || k.alg === alg));
 *     if (!key) throw new Error(`Key ${kid} not found`);
 *     return await crypto.subtle.importKey('jwk', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
 *   },
 *   checkExpiration: true
 * };
 * const result = await decodeSDJWT({ vcToken: token }, options);
 * ```
 */
export interface ValidationOptions {
  verifySignature?: boolean;
  checkExpiration?: boolean;
  validateDisclosureHashes?: boolean;
  signingKeyResolver?: KeyResolver;
  proofValidationOptions?: ProofValidationOptions;
}

/**
 * Structured input for SD-JWT decoding.
 *
 * @property vcToken - The SD-JWT or VC+SD-JWT token string to decode. This may be a combined
 * format token that already contains embedded disclosures.
 * @property selectiveDisclosures - Optional disclosures to apply during decoding. When provided
 * as a non-empty array, these disclosures replace any disclosures embedded in `vcToken`.
 */
export interface DecodeInputObject {
  vcToken: string;
  selectiveDisclosures?: string[];
}

/**
 * Input accepted by {@link decodeSDJWT}.
 *
 * May be either a raw token string or a structured object containing the token and optional
 * selective disclosures.
 */
export type DecodeInput = string | DecodeInputObject;

/**
 * Validates a JWT-based SD-JWT (Selective Disclosure JWT) token
 *
 * Performs comprehensive validation of tokens following the SD-JWT (RFC-9901) specification.
 * Supports both standard and compressed (DEFLATE) JWT formats. The function can:
 * - Parse SD-JWT combined format (JWT~disclosure~disclosure~...)
 * - Verify cryptographic signatures using public keys
 * - Validate expiration timestamps
 * - Verify selective disclosure hashes
 * - Extract and merge disclosed claims
 *
 * The validation process includes:
 * 1. JWT structure validation (header, payload, signature)
 * 2. Algorithm verification (RS256/384/512, ES256/384/512)
 * 3. Optional signature verification using provided public key
 * 4. Optional expiration check based on 'exp' claim
 * 5. Selective disclosure parsing and hash validation
 * 6. Schema validation against SD-JWT or VC+SD-JWT formats
 *
 * @template T - The token type extending SDJWT interface
 * @param input - Either:
 *                - A combined SD-JWT string in format: "JWT~disclosure1~disclosure2~..."
 *                - An object with `vcToken` and optional `selectiveDisclosures`
 *                  for separately transported disclosures.
 * @param options - Configuration options controlling validation behavior.
 *                  See {@link ValidationOptions} for detailed option descriptions
 * @returns Promise resolving to {@link DecodeResult} containing:
 *          - `valid`: true if all validations passed
 *          - `data`: parsed token data (if valid)
 *          - `disclosures`: extracted disclosed claims (if present)
 *          - `error`: descriptive error message (if validation failed)
 *
 * @example
 * Basic validation without signature verification:
 * ```typescript
 * const result = await decodeSDJWT(sdJwtToken);
 * if (result.valid) {
 *   console.log('Valid token:', result.data);
 * }
 * ```
 *
 * @example
 * Full validation with signature verification:
 * ```typescript
 * const publicKey = await crypto.subtle.importKey(
 *   'jwk',
 *   jwkPublicKey,
 *   { name: 'ECDSA', namedCurve: 'P-256' },
 *   true,
 *   ['verify']
 * );
 *
 * const result = await decodeSDJWT(sdJwtToken, {
 *   verifySignature: true,
 *   signingKeyResolver: async () => publicKey,
 *   checkExpiration: true,
 *   validateDisclosureHashes: true
 * });
 * ```
 *
 * @example
 * Full validation with signature verification and explicit disclosure array:
 * ```typescript
 * const result = await decodeSDJWT({
 *   vcToken: sdJwtToken,
 *   selectiveDisclosures: disclosureTokens,
 * }, {
 *   verifySignature: true,
 *   signingKeyResolver: async () => publicKey,
 *   checkExpiration: true,
 *   validateDisclosureHashes: true
 * });
 *
 * if (result.valid) {
 *   console.log('Token data:', result.data);
 *   console.log('Disclosed claims:', result.disclosures);
 * } else {
 *   console.error('Validation error:', result.error);
 * }
 * ```
 *
 * @example
 * Validation with dynamic key resolution using iss, kid, and alg:
 * ```typescript
 * const keyResolver: KeyResolver = async (iss, kid, alg) => {
 *   // Fetch JWKS from issuer
 *   const response = await fetch(`${iss}/.well-known/jwks.json`);
 *   const keySet = await response.json();
 *   const key = keySet.keys.find(k => k.kid === kid && (!alg || k.alg === alg));
 *
 *   if (!key) throw new Error(`Key ${kid} not found for issuer ${iss}`);
 *
 *   return await crypto.subtle.importKey(
 *     'jwk',
 *     key,
 *     { name: 'ECDSA', namedCurve: 'P-256' },
 *     false,
 *     ['verify']
 *   );
 * };
 *
 * const result = await decodeSDJWT({ vcToken: sdJwtToken }, {
 *   verifySignature: true,
 *   signingKeyResolver: keyResolver,
 * });
 *
 * ```
 *
 * @example
 * Validation with dynamic key resolution using iss, kid, and alg plus explicit disclosures:
 * ```typescript
 * const result = await decodeSDJWT({
 *   vcToken: sdJwtToken,
 *   selectiveDisclosures: disclosureTokens,
 * }, {
 *   verifySignature: true,
 *   signingKeyResolver: keyResolver,
 * });
 *
 * ```
 *
 * @see {@link ValidationOptions} for configuration options
 * @see {@link DecodeResult} for result structure
 * @see RFC-9901 for SD-JWT specification
 */
export const PROOF_MAX_AGE_SECONDS = 300;

export async function decodeSDJWT<T extends SDJWT = SDJWT>(
  input: DecodeInput,
  options: ValidationOptions = {}
): Promise<DecodeResult<T>> {
  try {
    const {
      verifySignature = true,
      checkExpiration = true,
      validateDisclosureHashes = true,
      signingKeyResolver: keyResolver,
      proofValidationOptions,
    } = options;

    const normalizedInput =
      typeof input === 'string' ? { vcToken: input, selectiveDisclosures: [] as string[] } : input;

    if (
      !normalizedInput ||
      typeof normalizedInput.vcToken !== 'string' ||
      normalizedInput.vcToken.length === 0
    ) {
      return {
        valid: false,
        error: 'Credential token is required',
      };
    }

    // Parse SD-JWT format (JWT~disclosure~disclosure~...)
    const parts = normalizedInput.vcToken.split('~');
    const originalJwtToken = parts[0];
    const embeddedDisclosureParts = parts.slice(1).filter((d) => d.length > 0);
    const explicitDisclosures = normalizedInput.selectiveDisclosures ?? [];
    const remainingTokenParts =
      explicitDisclosures.length > 0 ? explicitDisclosures : embeddedDisclosureParts;

    // Validate JWT structure
    const jwtParts = originalJwtToken.split('.');
    if (jwtParts.length !== 3) {
      return {
        valid: false,
        error: 'Invalid JWT format',
      };
    }

    // Parse JWT header
    let header: Record<string, unknown>;
    try {
      header = jose.decodeProtectedHeader(originalJwtToken);
    } catch {
      return {
        valid: false,
        error: 'Invalid JWT header',
      };
    }

    // Allowed algorithms for signature verification
    const ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
    const ALLOWED_TYPES = ['sd-jwt', 'vc+sd-jwt'];

    const headerAlg = typeof header.alg === 'string' ? header.alg : undefined;
    const headerZip = typeof header.zip === 'string' ? header.zip : undefined;
    const isCompressed = headerZip?.toUpperCase() === 'DEF';
    const type = typeof header.typ === 'string' ? header.typ.toLowerCase() : undefined;

    if (!type) {
      return {
        valid: false,
        error: 'Missing required JWT header field: typ',
      };
    }

    if (!ALLOWED_TYPES.includes(type)) {
      return {
        valid: false,
        error: `Unsupported JWT type: '${type}'. Allowed types: ${ALLOWED_TYPES.join(', ')}`,
      };
    }

    if (headerAlg && !ALLOWED_ALGORITHMS.includes(headerAlg)) {
      return {
        valid: false,
        error: `Unsupported signature algorithm: '${headerAlg}'`,
      };
    }

    // Decode JWT payload without verification
    let payload: jose.JWTPayload;
    if (isCompressed) {
      try {
        payload = JSON.parse(decompressString(jwtParts[1]));
      } catch (err) {
        return {
          valid: false,
          error: `Failed to decompress JWT payload: ${err instanceof Error ? err.message : 'Unknown error'}`,
        };
      }
    } else {
      payload = jose.decodeJwt(originalJwtToken);
    }

    // Verify signature and decode JWT payload
    let resolvedPublicKey: CryptoKey | Uint8Array | undefined;

    if (verifySignature) {
      // Resolve key dynamically using keyResolver with iss, kid, and alg
      if (keyResolver) {
        try {
          // Extract kid from JWT header
          const kid = typeof header.kid === 'string' ? header.kid : undefined;
          const alg = typeof header.alg === 'string' ? header.alg : undefined;
          const iss = typeof payload.iss === 'string' ? payload.iss : undefined;

          if (!iss) {
            return {
              valid: false,
              error: 'Cannot resolve public key: missing iss claim in token for key resolution',
            };
          }

          resolvedPublicKey = await keyResolver(iss, kid, alg);
        } catch (err) {
          return {
            valid: false,
            error: `Key resolution failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
          };
        }
      }

      if (!resolvedPublicKey) {
        return {
          valid: false,
          error: 'Public key required for signature verification (provide signingKeyResolver)',
        };
      }

      try {
        if (isCompressed) {
          // For compressed JWTs, use compactVerify (signature verification only)
          await jose.compactVerify(originalJwtToken, resolvedPublicKey, {
            algorithms: ALLOWED_ALGORITHMS,
          });
        } else {
          // For non-compressed JWTs, use jwtVerify which handles everything
          await jose.jwtVerify(originalJwtToken, resolvedPublicKey, {
            algorithms: ALLOWED_ALGORITHMS,
          });
        }
      } catch (err) {
        return {
          valid: false,
          error: `Signature verification failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        };
      }
    }

    // Parse selective disclosures if present
    const rawDisclosures: Record<string, unknown> = {};
    const disclosures: Record<string, unknown> = {};
    const disclosureStrings: string[] = [];
    for (const part of remainingTokenParts) {
      try {
        const decodedDisclosure = JSON.parse(base64urlToString(part)) as unknown;
        if (Array.isArray(decodedDisclosure) && decodedDisclosure.length >= 3) {
          // SD-JWT disclosure format: [salt, claim_name, claim_value]
          const claimName: unknown = decodedDisclosure[1];
          const claimValue: unknown = decodedDisclosure[2];
          if (typeof claimName === 'string') {
            rawDisclosures[claimName] = part;
            disclosures[claimName] = claimValue;
            disclosureStrings.push(part);
          }
        }
      } catch {
        // Invalid disclosure format, skip
        continue;
      }
    }

    // Validate disclosure hashes if required and _sd array is present
    if (validateDisclosureHashes && payload._sd && Array.isArray(payload._sd)) {
      const hashAlg =
        payload._sd_alg && typeof payload._sd_alg === 'string' ? payload._sd_alg : 'sha-256';
      const sdHashes = payload._sd as string[];

      try {
        await verifyDisclosureHashes(disclosureStrings, sdHashes, hashAlg);
      } catch (err) {
        return {
          valid: false,
          error: `Disclosure hash validation failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        };
      }
    }

    // Extract token data from JWT payload
    const data = extractCredentialFromPayload<T>(payload, type);

    if (!data) {
      return {
        valid: false,
        error: 'Invalid token format in JWT payload',
      };
    }

    // Check expiration if required
    if (checkExpiration && payload.exp) {
      const now = getCurrentUnixTime();
      if (payload.exp < now) {
        return {
          valid: false,
          data: data,
          error: 'Token has expired',
        };
      }
    }
    const decodedData = {
      data,
      disclosures: Object.keys(disclosures).length > 0 ? disclosures : undefined,
      rawData: originalJwtToken,
      rawDisclosures: Object.keys(rawDisclosures).length > 0 ? rawDisclosures : undefined,
    };

    if (proofValidationOptions) {
      const proof = remainingTokenParts.pop();
      const proofResult = await validateProof(originalJwtToken, proof, proofValidationOptions);
      const { valid, status, proofIssuedAt } = proofResult;
      const proofIssuedAtDate =
        typeof proofIssuedAt === 'number' ? new Date(proofIssuedAt * 1000) : undefined;
      return {
        ...decodedData,
        valid,
        status,
        proofIssuedAt: proofIssuedAtDate,
      };
    } else {
      return {
        ...decodedData,
        valid: true,
      };
    }
  } catch (err) {
    return {
      valid: false,
      status: PresentationVerificationStatus.INVALID_PROOF,
      error: `Validation failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
    };
  }
}

/**
 * Extract and validate an SD-JWT Credential from JWT payload
 *
 * Parses the JWT payload and validates it against the appropriate JSON schema
 * based on the JWT header's typ field. Returns null if validation fails or type is unknown.
 *
 * @template T - The credential type extending SDJWT interface
 * @param payload - The decoded JWT payload object
 * @param type - The JWT typ field value (must be 'sd-jwt' or 'vc+sd-jwt')
 * @returns The validated credential of type T, or null if validation fails or type is unknown
 *
 * @remarks
 * - For typ='vc+sd-jwt': Validates against VC+SD-JWT schema (requires vct field)
 * - For typ='sd-jwt': Validates against SD-JWT schema (allows additional properties)
 * - Returns null on schema validation failure but does not throw errors
 */
function extractCredentialFromPayload<T extends SDJWT>(
  payload: jose.JWTPayload,
  type: string
): T | null {
  const credential = {
    ...payload,
  } as T;

  // Validate against JSON schema
  try {
    if (type === 'vc+sd-jwt') {
      validateVCSDJWTAgainstSchema(credential);
    } else if (type === 'sd-jwt') {
      validateSDJWTAgainstSchema(credential);
    } else {
      return null;
    }
  } catch {
    // Schema validation failed
    return null;
  }

  // Validate cnf constraints for VC+SD-JWT
  if (type === 'vc+sd-jwt' && 'cnf' in credential) {
    const cnf = credential.cnf as Record<string, unknown>;
    const hasJwk = 'jwk' in cnf;
    const hasJkt = 'jkt' in cnf;

    // cnf must have at least one of jwk or jkt
    if (!hasJwk && !hasJkt) {
      return null;
    }

    // cnf cannot have both jwk and jkt
    if (hasJwk && hasJkt) {
      return null;
    }
  }

  return credential;
}

/**
 * Verify that disclosure hashes match the token's _sd array
 *
 * Computes hashes for all provided disclosures and verifies each exists in the JWT's
 * _sd array. This ensures selective disclosures have not been tampered with and are
 * authorized by the issuer.
 *
 * @param disclosures - Array of base64url-encoded disclosure strings to verify
 * @param sdHashes - Array of expected hashes from the JWT's _sd field
 * @param algorithm - Hash algorithm specified in the JWT's _sd_alg field (default: 'sha-256')
 * @throws {Error} If any computed disclosure hash is not found in the _sd array
 * @throws {Error} If hash algorithm is unsupported
 *
 * @remarks
 * - Each disclosure hash must exactly match an entry in sdHashes (no partial matches)
 * - The _sd array may contain more hashes than provided disclosures (some claims remain undisclosed)
 * - All disclosures provided must have corresponding hashes in _sd array
 * - Prevents disclosure tampering by detecting hash mismatches
 */
async function verifyDisclosureHashes(
  disclosures: string[],
  sdHashes: string[],
  algorithm: string
): Promise<void> {
  // Compute hashes for all disclosures
  const computedHashes = await Promise.all(
    disclosures.map(async (d) => uint8ArrayToBase64url(await computeHash(d, algorithm)))
  );

  // Check that each computed hash exists in the _sd array
  for (const hash of computedHashes) {
    if (!sdHashes.includes(hash)) {
      throw new Error(`Disclosure hash ${hash} not found in _sd array`);
    }
  }
}

/**
 * Checks whether an SD-JWT token has expired based on its expiration timestamp
 *
 * Evaluates the token's 'exp' (expiration time) claim against the current time.
 * The 'exp' claim must contain a NumericDate value representing seconds since Unix epoch
 * (January 1, 1970 00:00:00 UTC) as defined in RFC 7519 (JWT specification).
 *
 * @param credential - The SD-JWT token to check for expiration
 * @returns `true` if the token has expired (exp < current time in Unix epoch seconds),
 *          `false` if the token is still valid or has no expiration date
 *
 * @remarks
 * - If the token does not have an 'exp' claim, it is considered non-expiring
 *   and this function returns `false`
 * - All timestamp comparisons use Unix epoch time in **seconds** (not milliseconds)
 * - The function converts `Date.now()` (milliseconds) to seconds for comparison
 * - This check can also be performed automatically during validation by setting
 *   `checkExpiration: true` in {@link ValidationOptions}
 * - All JWT timestamp fields (exp, iat, nbf) follow the same Unix epoch convention
 *
 * @example
 * ```typescript
 * const result = await decodeSDJWT(token, { checkExpiration: false });
 * if (result.valid) {
 *   const expired = isSDJWTExpired(result.data);
 *   if (expired) {
 *     console.log('Token has expired');
 *   } else {
 *     console.log('Token is still valid');
 *   }
 * }
 * ```
 *
 * @see {@link ValidationOptions.checkExpiration} for automatic expiration checking
 * @see RFC 7519 Section 2 for NumericDate definition
 */
export function isSDJWTExpired(credential: SDJWT): boolean {
  if (!credential.exp) {
    return false;
  }

  const now = getCurrentUnixTime();
  return credential.exp < now;
}

async function validateProof(
  originalJwtToken: string,
  proof?: string,
  proofValidationOptions?: ProofValidationOptions
) {
  if (!proof) {
    return {
      valid: false,
      status: PresentationVerificationStatus.INVALID_MISSING_PROOF,
      error: 'Invalid CKAPP presentation: missing proof',
    };
  } else if (proofValidationOptions?.proofType === ProofTypeEnum.CKAPP) {
    try {
      return await decodeCKAPP(proof, originalJwtToken, proofValidationOptions);
    } catch (error) {
      return {
        valid: false,
        error: `Invalid CKAPP proof: ${error as Error}`,
        status: PresentationVerificationStatus.INVALID_PROOF,
      };
    }
  } else if (proofValidationOptions?.proofType === ProofTypeEnum.SECURE_QR) {
    try {
      return await decodeSecureQr(proof, originalJwtToken, proofValidationOptions);
    } catch (error) {
      return {
        valid: false,
        error: `Invalid SecureQR proof: ${error as Error}`,
        status: PresentationVerificationStatus.INVALID_PROOF,
      };
    }
  }
  return {
    valid: false,
    error: 'Unsupported proof type',
    status: PresentationVerificationStatus.INVALID_PROOF,
  };
}
