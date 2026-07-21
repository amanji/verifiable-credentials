import * as jose from 'jose';
import type { FederationDiscoveryOptions, EntityMetadata } from './types';
import { validateEntityStatementSchema } from './schema-validator';

const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';

interface FederationConstraints {
  max_path_length?: number;
  naming_constraints?: {
    permitted?: string[];
    excluded?: string[];
  };
  allowed_entity_types?: string[];
  [key: string]: unknown;
}

interface MetadataParameterPolicy {
  value?: unknown;
  add?: unknown[];
  default?: unknown;
  one_of?: unknown[];
  subset_of?: unknown[];
  superset_of?: unknown[];
  essential?: boolean;
  [operator: string]: unknown;
}

type MetadataPolicy = Record<string, Record<string, MetadataParameterPolicy>>;

export interface FederationEntityStatement {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  jwks: { keys: unknown[] };
  metadata?: EntityMetadata;
  authority_hints?: string[];
  trust_anchor_hints?: string[];
  metadata_policy?: MetadataPolicy;
  metadata_policy_crit?: string[];
  constraints?: FederationConstraints;
  source_endpoint?: string;
  [key: string]: unknown;
}

export interface ParsedEntityStatement {
  jwt: string;
  header: Record<string, unknown>;
  payload: FederationEntityStatement;
}

/**
 * Ensures decoded JOSE/JWT structures are objects before further validation.
 */
function asRecord(value: unknown, errorPrefix: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${errorPrefix} is not an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Computes current NumericDate used by iat/exp checks.
 */
function normalizeNow(options: FederationDiscoveryOptions): number {
  return options.now ? options.now() : Math.trunc(Date.now() / 1000);
}

/**
 * Applies validation leeway for clock skew around JWT timestamps.
 */
function normalizeClockSkew(options: FederationDiscoveryOptions): number {
  return options.clockSkewSeconds ?? 30;
}

/**
 * Verifies a signed JWT using the matching federation signing key by `kid`.
 */
async function verifyJwsWithJwks(jwt: string, jwks: { keys: unknown[] }): Promise<void> {
  const header = jose.decodeProtectedHeader(jwt);
  if (!header.kid || typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new Error('Missing required kid in JWT header');
  }

  const candidates = (jwks.keys ?? []).filter((key): key is JsonWebKey & { kid?: string } => {
    if (typeof key !== 'object' || key === null || Array.isArray(key)) {
      return false;
    }

    return (key as { kid?: unknown }).kid === header.kid;
  });
  if (candidates.length === 0) {
    throw new Error(`No matching key for kid ${header.kid}`);
  }

  let lastError: unknown;
  for (const jwk of candidates) {
    try {
      const keyLike = await jose.importJWK(
        jwk,
        typeof header.alg === 'string' ? header.alg : undefined
      );
      await jose.jwtVerify(jwt, keyLike, {
        algorithms: header.alg && header.alg !== 'none' ? [header.alg] : undefined,
      });
      return;
    } catch (error) {
      lastError = error;
    }
  }

  const errorSuffix = lastError instanceof Error ? `: ${lastError.message}` : '';
  throw new Error(`Signature verification failed${errorSuffix}`);
}

/**
 * Validates mandatory JOSE header requirements (`typ`, `alg`, `kid`).
 */
function validateStatementHeader(header: Record<string, unknown>, expectedTyp: string): void {
  if (header.typ !== expectedTyp) {
    throw new Error(`Invalid JWT typ, expected ${expectedTyp}`);
  }

  if (typeof header.alg !== 'string' || header.alg === 'none') {
    throw new Error('Invalid JWT alg header');
  }

  if (typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new Error('Missing required kid in JWT header');
  }
}

/**
 * Parses and validates an Entity Statement JWT payload and headers.
 */
export function parseEntityStatementJwt(jwt: string): ParsedEntityStatement {
  const header = asRecord(jose.decodeProtectedHeader(jwt), 'Entity statement header');
  validateStatementHeader(header, ENTITY_STATEMENT_TYP);

  const payload = asRecord(jose.decodeJwt(jwt), 'Entity statement payload');
  validateEntityStatementSchema(payload);

  return {
    jwt,
    header,
    payload: payload as unknown as FederationEntityStatement,
  };
}

/**
 * Validates trust chain structure, timestamps, issuer/subject continuity, and signatures.
 */
export async function verifyTrustChain(
  chain: string[],
  trustAnchors: string[],
  options: FederationDiscoveryOptions
): Promise<{ statements: ParsedEntityStatement[]; expiresAt: number; trustAnchor: string }> {
  if (chain.length < 2) {
    throw new Error('Trust chain must contain at least two statements');
  }

  const statements = chain.map(parseEntityStatementJwt);
  return verifyTrustChainStatements(statements, trustAnchors, options);
}

export async function verifyTrustChainStatements(
  statements: ParsedEntityStatement[],
  trustAnchors: string[],
  options: FederationDiscoveryOptions
): Promise<{ statements: ParsedEntityStatement[]; expiresAt: number; trustAnchor: string }> {
  if (statements.length < 2) {
    throw new Error('Trust chain must contain at least two statements');
  }

  const now = normalizeNow(options);
  const skew = normalizeClockSkew(options);

  if (statements[0].payload.iss !== statements[1].payload.sub) {
    throw new Error(
      'Trust chain is broken: first statement issuer must match the second statement subject'
    );
  }

  for (const statement of statements) {
    if (statement.payload.iat > now + skew) {
      throw new Error(`Entity statement iat is in the future for ${statement.payload.sub}`);
    }
    if (statement.payload.exp < now - skew) {
      throw new Error(`Entity statement expired for ${statement.payload.sub}`);
    }
  }

  await verifyJwsWithJwks(statements[0].jwt, statements[0].payload.jwks);

  for (let index = 0; index < statements.length - 1; index += 1) {
    const current = statements[index];
    const next = statements[index + 1];

    if (current.payload.iss !== next.payload.sub) {
      throw new Error(`Invalid chain continuity at index ${index}`);
    }

    await verifyJwsWithJwks(current.jwt, current.payload.jwks);
  }

  const trustAnchorStatement = statements[statements.length - 1];
  const trustAnchorId = trustAnchorStatement.payload.sub;

  if (trustAnchorStatement.payload.iss !== trustAnchorId) {
    throw new Error('Last trust chain element must be a trust anchor entity configuration');
  }

  if (!trustAnchors.includes(trustAnchorId)) {
    throw new Error(`Trust anchor ${trustAnchorId} is not trusted`);
  }

  await verifyJwsWithJwks(trustAnchorStatement.jwt, trustAnchorStatement.payload.jwks);

  const expiresAt = Math.min(...statements.map((statement) => statement.payload.exp));
  return {
    statements,
    expiresAt,
    trustAnchor: trustAnchorId,
  };
}
