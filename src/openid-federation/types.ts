/**
 * Input payload for OpenID Federation entity discovery.
 *
 * Both `entityId` and each value in `trustAnchors` may be provided as `string` or `URL`.
 * They are normalized internally and must resolve to HTTPS identifiers.
 */
export interface FederationDiscoveryRequest {
  /** Entity identifier to discover, for example `https://wallet.example.org`. */
  entityId: string | URL;
  /** Trusted entity identifiers for acceptable trust anchors. */
  trustAnchors: Array<string | URL>;
}

/**
 * Enumeration of supported discovery strategies.
 */
export enum DiscoveryStrategy {
  federation_fetch_endpoint = 'federation_fetch_endpoint',
  issuer_endpoint = 'issuer_endpoint',
}

/**
 * Runtime options that control validation and transport behavior.
 *
 * All fields are optional. Defaults are applied by the discovery implementation.
 */
export interface FederationDiscoveryOptions {
  /** Optional fetch implementation. Falls back to `globalThis.fetch` when available. */
  fetcher?: typeof fetch;
  /** Discovery strategy to use. Default: `['federation_fetch_endpoint']`. Order of strategies determines priority. */
  discoveryStrategy?: DiscoveryStrategy[];
  /** Maximum number of `authority_hints` processed per statement (default: 20). */
  maxAuthorityHints?: number;
  /** Maximum local trust-chain recursion depth (default: 10). */
  maxChainDepth?: number;
  /** Allowed clock skew in seconds for `iat`/`exp` validation (default: 30). */
  clockSkewSeconds?: number;
  /**
   * Time source in seconds since epoch.
   * Useful for deterministic tests.
   */
  now?: () => number;
}

/**
 * Result envelope for federation discovery.
 *
 * Inspect `valid` first, then use either `data` or `error`.
 */
export interface FederationDiscoveryResult {
  /** `true` when discovery and validation succeed. */
  valid: boolean;
  /** Present only when `valid` is `true`. */
  data?: ResolvedFederationEntity;
  /** Present only when `valid` is `false`. */
  error?: FederationError;
}

/**
 * Resolved federation entity output.
 *
 * Returned only when `FederationDiscoveryResult.valid` is `true`.
 */
export interface ResolvedFederationEntity {
  /** Subject entity identifier that was requested. */
  subject: string;
  /** Trust anchor selected from the validated chain. */
  trustAnchor: string;
  /** Earliest expiration timestamp across validated artifacts (NumericDate). */
  expiresAt: number;
  /**
   * Raw metadata from the discovered subject (leaf) entity configuration.
   * Note: `metadata_policy` and `metadata_policy_crit` from superior entities
   * in the trust chain are NOT applied here; callers must apply any policies
   * themselves if required.
   */
  metadata: EntityMetadata;
  /** JWT chain used for the final resolution decision. */
  trustChain: string[];
}

/**
 * Input payload for listing subordinate entities of one or more trust anchors.
 */
export interface DiscoverEntitiesRequest {
  /** Trust anchor entity identifiers to query. */
  trustAnchors: Array<string | URL>;
}

/**
 * Result envelope for entity listing.
 *
 * Inspect `valid` first, then use either `entityUris` or `error`.
 */
export interface DiscoverEntitiesResult {
  /** `true` when the list was fetched and parsed successfully. */
  valid: boolean;
  /** Present only when `valid` is `true`. Subordinate entity identifier URIs. */
  entityUris?: URL[];
  /** Present only when `valid` is `false`. */
  error?: FederationError;
}

/**
 * Federation metadata map keyed by entity type.
 * Example key: `openid_relying_party`, `openid_provider`, `federation_entity`.
 */
export type EntityMetadata = Record<string, Record<string, unknown>>;

/**
 * Typed error model for discovery callers.
 *
 * Returned only when `FederationDiscoveryResult.valid` is `false`.
 */
export interface FederationError {
  /** Programmatic error code suitable for branching in consumers. */
  code:
    | 'InvalidInput'
    | 'NetworkError'
    | 'InvalidJwtType'
    | 'SchemaValidationFailed'
    | 'TrustChainInvalid'
    | 'Unsupported';
  /** Human-readable detail for logs and diagnostics. */
  message: string;
  /** Optional original thrown value from lower-level validation or transport code. */
  cause?: unknown;
}
