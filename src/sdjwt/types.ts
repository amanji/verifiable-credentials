import { KeyResolver } from './decode';

/**
 * Type definitions for SD-JWT
 * Based on SD-JWT (RFC-9901) and VC+SD-JWT schema specifications
 *
 * @remarks
 * All timestamp fields (exp, iat, nbf) use Unix epoch time format:
 * - Measured in **seconds** (not milliseconds) since January 1, 1970 00:00:00 UTC
 * - Also known as NumericDate in RFC 7519 (JWT specification)
 * - To convert from JavaScript Date.now(): Math.trunc(Date.now() / 1000)
 */

/**
 * Status List entry (IETF Status List 2021)
 * Used to track the status of a token for revocation or suspension
 */
export interface StatusList {
  /** URL pointing to the status list resource */
  status_list_uri: string;
  /** Index in the status list array corresponding to this credential */
  status_list_index: number;
}

/**
 * Confirmation claim for key binding
 * Provides proof-of-possession mechanism by binding the credential to a specific key
 * Supports both full public JWK or JWK Thumbprint depending on use case
 *
 * @remarks
 * - Exactly one of jwk or jkt must be present (never both)
 * - jwk: Full JSON Web Key object for direct key verification
 * - jkt: JWK Thumbprint (RFC 7638) for bandwidth/privacy optimization
 */
export interface KeyBindingConfirmation {
  /** Full JSON Web Key for holder's public key */
  jwk?: Record<string, unknown>;
  /** JWK Thumbprint (SHA-256 hash of canonical JWK representation) */
  jkt?: string;
}

/**
 * SD-JWT Token (RFC-9901)
 * Base type for Selective Disclosure JWT tokens
 *
 * Represents an SD-JWT token that supports selective disclosure of claims,
 * allowing issuers to create tokens where some claims can be hidden/revealed
 * independently. Each disclosed claim is cryptographically bound via hash.
 *
 * @remarks
 * All timestamp fields use NumericDate format (RFC 7519):
 * - Integer **seconds** since Unix epoch (January 1, 1970 00:00:00 UTC)
 * - NOT milliseconds - convert from Date.now() by dividing by 1000
 * - Comparison: Math.trunc(Date.now() / 1000) for current time
 *
 * Selective disclosure fields:
 * - _sd is an optional array containing base64url-encoded hashes of selectively disclosable claims
 * - _sd_alg is an optional hash algorithm identifier for the values in _sd
 * - If _sd is present and _sd_alg is omitted, implementations default to the 'sha-256' algorithm
 * - Only 'sha-256' is currently supported as a hash algorithm
 *
 * @see RFC-9901 for complete SD-JWT specification
 */
export interface SDJWT {
  /** JSON Web Token ID (optional) */
  jti?: string;
  /** Not Before timestamp - Unix epoch in seconds (optional) */
  nbf?: number;
  /** Issuer URI (required) */
  iss: string;
  /** Issued At timestamp - Unix epoch in seconds (required) */
  iat: number;
  /** Subject Identifier (optional) */
  sub?: string;
  /** Expiry timestamp - Unix epoch in seconds (optional) */
  exp?: number;
  /** Status information (optional) */
  status?: StatusList;
  /** Array of selectively disclosed claim digests (optional) */
  _sd?: string[];
  /** Hash algorithm used for SD-JWT disclosure digests (optional, enum: ["sha-256"]) */
  _sd_alg?: 'sha-256';
  /** Additional claims */
  [key: string]: unknown;
}

/**
 * VC+SD-JWT Token
 * Extends SD-JWT with Verifiable Credential Type Profile and key binding
 *
 * Used in OpenID4VC scenarios where tokens must include type information
 * and optionally bind holder public keys for presentation. Stricter than base
 * SD-JWT as it requires the vct field.
 *
 * @remarks
 * - Inherits all SD-JWT features and constraints
 * - Requires vct field (Type) - must be valid URI
 * - vct identifies the token type/schema (e.g., "https://credentials.example.com/identity")
 * - cnf field optional for holder key binding
 * - Used in standards like OpenID4VC for interoperable token exchange
 *
 * @see {@link SDJWT} for inherited fields and behavior
 * @see RFC-9901 for SD-JWT base specification
 */
export interface VCSDJWT extends SDJWT {
  /** Type Profile URI (required) */
  vct: string;
  /** Confirmation Claim for Key-Binding (optional) */
  cnf?: KeyBindingConfirmation;
}

export interface CKAPPProofValidationOptions {
  proofType: ProofTypeEnum;
  expectedNonce?: Uint8Array;
  proofSigningKeyResolver: KeyResolver;
}

export interface SecureQRProofValidationOptions {
  proofType: ProofTypeEnum;
  proofSigningKeyResolver: KeyResolver;
}

export enum PresentationVerificationStatus {
  VALID = 'valid',
  VALID_MISSING_PROOF = 'valid_missing_proof',
  INVALID_MISSING_PROOF = 'invalid_missing_proof',
  INVALID_PROOF = 'invalid_proof',
  WARNING_PROOF_OLD = 'warning_proof_old',
  INVALID_PROOF_OLD = 'invalid_proof_old',
}

export enum ProofTypeEnum {
  CKAPP = 'ckapp',
  SECURE_QR = 'secure-qr-jwt',
}
