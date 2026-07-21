import {
  DiscoveryStrategy,
  DiscoverEntitiesRequest,
  DiscoverEntitiesResult,
  FederationDiscoveryOptions,
  FederationDiscoveryRequest,
  FederationDiscoveryResult,
  FederationError,
  ResolvedFederationEntity,
} from './types';
import type { ParsedEntityStatement } from './verification';
import { parseEntityStatementJwt, verifyTrustChainStatements } from './verification';
import { validateEndpointErrorSchema } from './schema-validator';

const WELL_KNOWN_PATH = '/.well-known/openid-federation';

class DiscoveryAggregateError extends Error {
  constructor(public readonly flowErrors: Array<{ strategy: DiscoveryStrategy; error: Error }>) {
    const details = flowErrors
      .map(({ strategy, error }) => `${strategy}: ${error.message}`)
      .join('; ');
    super(`Discovery failed via configured strategies. ${details}`);
    this.name = 'DiscoveryAggregateError';
  }
}

interface LocalChainTraversalContext {
  currentEntityId: string;
  entityJwt: string;
  trustAnchors: string[];
  options: FederationDiscoveryOptions;
  fetcher: typeof fetch;
  visited: Set<string>;
  depth: number;
}

function ensureHttpsEntityId(entityId: string | URL): URL {
  const url = new URL(entityId.toString());
  if (url.protocol !== 'https:') {
    throw new Error('Entity identifier must use the https scheme');
  }
  if (!url.hostname) {
    throw new Error('Entity identifier must include a host');
  }
  if (url.search || url.hash) {
    throw new Error('Entity identifier must not include query or fragment');
  }
  return url;
}

function toCanonicalEntityId(entityId: URL): string {
  if (entityId.pathname === '/' && !entityId.search && !entityId.hash) {
    return entityId.origin;
  }

  return entityId.toString();
}

function buildEntityConfigurationUrl(entityId: URL): string {
  const url = new URL(entityId.toString());
  const basePath = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname;
  const effectivePath = `${basePath}${WELL_KNOWN_PATH}`;
  url.pathname = effectivePath;
  url.search = '';
  url.hash = '';
  return url.toString();
}

function normalizeFetcher(fetcher?: typeof fetch): typeof fetch {
  const selected = fetcher ?? globalThis.fetch;
  if (!selected) {
    throw new Error('No fetch implementation available');
  }
  return selected;
}

function normalizeOptions(
  optionsInput: FederationDiscoveryOptions = {}
): FederationDiscoveryOptions {
  return {
    fetcher: normalizeFetcher(optionsInput.fetcher),
    discoveryStrategy: optionsInput.discoveryStrategy ?? [
      DiscoveryStrategy.federation_fetch_endpoint,
    ],
    maxAuthorityHints: optionsInput.maxAuthorityHints ?? 20,
    maxChainDepth: optionsInput.maxChainDepth ?? 10,
    clockSkewSeconds: optionsInput.clockSkewSeconds ?? 30,
    now: optionsInput.now ?? (() => Math.trunc(Date.now() / 1000)),
  };
}

async function parseEndpointError(response: Response): Promise<string | undefined> {
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return undefined;
  }

  try {
    const payload = await response.json();
    validateEndpointErrorSchema(payload);
    return `${payload.error}: ${payload.error_description}`;
  } catch {
    return undefined;
  }
}

async function fetchEntityConfiguration(
  entityId: URL,
  fetcher: typeof fetch
): Promise<ParsedEntityStatement> {
  const response = await fetcher(buildEntityConfigurationUrl(entityId));

  if (!response.ok) {
    const endpointError = await parseEndpointError(response);
    throw new Error(endpointError ?? `Failed to fetch entity configuration for ${entityId}`);
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/entity-statement+jwt')) {
    throw new Error(`Unexpected content-type for entity configuration: ${contentType}`);
  }

  const body = await response.text();
  const parsed = parseEntityStatementJwt(body);
  sanitizeStatementJwks(parsed);
  const normalizedEntityId = toCanonicalEntityId(entityId);
  if (parsed.payload.sub !== normalizedEntityId || parsed.payload.iss !== normalizedEntityId) {
    throw new Error(`Entity configuration mismatch for ${normalizedEntityId}`);
  }

  return parsed;
}

function sanitizeStatementJwks(statement: ParsedEntityStatement): void {
  const jwks = statement.payload.jwks;
  if (!jwks || !Array.isArray(jwks.keys)) {
    return;
  }

  jwks.keys = jwks.keys.map((key) => {
    if (typeof key !== 'object' || key === null || Array.isArray(key)) {
      return key;
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { oth, key_ops, ...sanitizedKey } = key as Record<string, unknown>;
    return sanitizedKey;
  });
}

function getFetchEndpoint(entityConfig: ParsedEntityStatement): string {
  const metadata = entityConfig.payload.metadata;
  const federationEntity = metadata?.federation_entity;
  const endpoint = federationEntity?.federation_fetch_endpoint;

  if (typeof endpoint !== 'string') {
    throw new TypeError(`Missing federation_fetch_endpoint in ${entityConfig.payload.sub}`);
  }

  return endpoint;
}

async function fetchSubordinateStatement(
  issuerEntityConfig: ParsedEntityStatement,
  subordinateEntityId: string,
  fetcher: typeof fetch
): Promise<ParsedEntityStatement> {
  const endpoint = getFetchEndpoint(issuerEntityConfig);
  const url = new URL(endpoint);
  url.searchParams.set('sub', subordinateEntityId);

  const response = await fetcher(url.toString());
  if (!response.ok) {
    const endpointError = await parseEndpointError(response);
    throw new Error(
      endpointError ??
        `Failed to fetch subordinate statement from ${issuerEntityConfig.payload.sub} for ${subordinateEntityId}`
    );
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/entity-statement+jwt')) {
    throw new Error(`Unexpected content-type for subordinate statement: ${contentType}`);
  }

  const statementJwt = await response.text();
  const statement = parseEntityStatementJwt(statementJwt);
  sanitizeStatementJwks(statement);
  if (
    statement.payload.iss !== issuerEntityConfig.payload.sub ||
    statement.payload.sub !== subordinateEntityId
  ) {
    throw new Error('Invalid subordinate statement issuer/subject relation');
  }

  return statement;
}

async function resolveStatementsFromChain(
  chain: string[],
  trustAnchors: string[],
  options: FederationDiscoveryOptions
): Promise<{ statements: ParsedEntityStatement[]; expiresAt: number; trustAnchor: string }> {
  const statements = chain.map((jwt) => {
    const statement = parseEntityStatementJwt(jwt);
    sanitizeStatementJwks(statement);
    return statement;
  });

  return verifyTrustChainStatements(statements, trustAnchors, options);
}

function appendSuperiorChains(
  chains: string[][],
  entityJwt: string,
  subordinateJwt: string,
  superiorChains: string[][]
): void {
  for (const chain of superiorChains) {
    const tail = chain.length === 1 ? chain : chain.slice(1);
    chains.push([entityJwt, subordinateJwt, ...tail]);
  }
}

async function collectChainsForAuthorityHint(
  superiorEntityId: string,
  context: LocalChainTraversalContext
): Promise<string[][]> {
  const nextVisited = new Set(context.visited);
  nextVisited.add(superiorEntityId);

  const superiorEntityConfig = await fetchEntityConfiguration(
    ensureHttpsEntityId(superiorEntityId),
    context.fetcher
  );
  const subordinateStatement = await fetchSubordinateStatement(
    superiorEntityConfig,
    context.currentEntityId,
    context.fetcher
  );
  const superiorChains = await buildLocalChains(
    superiorEntityConfig,
    context.trustAnchors,
    context.options,
    context.fetcher,
    nextVisited,
    context.depth + 1
  );
  const chains: string[][] = [];
  appendSuperiorChains(chains, context.entityJwt, subordinateStatement.jwt, superiorChains);
  return chains;
}

async function buildLocalChains(
  entityConfig: ParsedEntityStatement,
  trustAnchors: string[],
  options: FederationDiscoveryOptions,
  fetcher: typeof fetch,
  visited: Set<string>,
  depth: number
): Promise<string[][]> {
  if (depth > (options.maxChainDepth ?? 10)) {
    throw new Error('Maximum chain depth exceeded');
  }

  const currentEntityId = entityConfig.payload.sub;

  if (trustAnchors.includes(currentEntityId)) {
    return [[entityConfig.jwt]];
  }

  const authorityHints = entityConfig.payload.authority_hints ?? [];
  if (authorityHints.length === 0) {
    return [];
  }

  if (authorityHints.length > (options.maxAuthorityHints ?? 20)) {
    throw new Error(`Too many authority_hints for ${currentEntityId}`);
  }

  const chains: string[][] = [];

  for (const superiorEntityId of authorityHints) {
    if (visited.has(superiorEntityId)) {
      continue;
    }

    try {
      const superiorChains = await collectChainsForAuthorityHint(superiorEntityId, {
        currentEntityId,
        entityJwt: entityConfig.jwt,
        trustAnchors,
        options,
        fetcher,
        visited,
        depth,
      });
      chains.push(...superiorChains);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.debug(
        `Failed to build local chain for ${currentEntityId} via ${superiorEntityId}: ${reason}`
      );
    }
  }

  return chains;
}

function chooseBestChain(chains: string[][]): string[] {
  if (chains.length === 0) {
    throw new Error('No trust chain found from subject to a configured trust anchor');
  }

  return [...chains].sort((left, right) => left.length - right.length)[0];
}

function buildResolvedFromValidatedChain(
  subjectEntityId: string,
  statements: ParsedEntityStatement[],
  expiresAt: number,
  trustAnchor: string
): ResolvedFederationEntity {
  const subjectMetadata = statements[0].payload.metadata ?? {};

  return {
    subject: subjectEntityId,
    trustAnchor,
    expiresAt,
    metadata: subjectMetadata,
    trustChain: statements.map((statement) => statement.jwt),
  };
}

async function discoverViaFetchEndpointFlow(
  request: FederationDiscoveryRequest,
  options: FederationDiscoveryOptions
): Promise<ResolvedFederationEntity> {
  const fetcher = options.fetcher!;

  const entityId = toCanonicalEntityId(request.entityId as URL);
  const trustAnchors = request.trustAnchors.map((anchor) => toCanonicalEntityId(anchor as URL));

  const anchorErrors: string[] = [];

  // Try fetching the leaf entity from each trust anchor's federation_fetch_endpoint
  for (const trustAnchorUrl of request.trustAnchors as URL[]) {
    try {
      const trustAnchorConfig = await fetchEntityConfiguration(trustAnchorUrl, fetcher);
      const leafStatement = await fetchSubordinateStatement(trustAnchorConfig, entityId, fetcher);

      // Build a simple chain: [leaf, trust anchor]
      const chain = [leafStatement.jwt, trustAnchorConfig.jwt];
      const validated = await resolveStatementsFromChain(chain, trustAnchors, options);

      return buildResolvedFromValidatedChain(
        entityId,
        validated.statements,
        validated.expiresAt,
        validated.trustAnchor
      );
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      anchorErrors.push(`${toCanonicalEntityId(trustAnchorUrl)} => ${reason}`);
      // Try next trust anchor
      continue;
    }
  }

  throw new Error(
    `Failed to discover entity via fetch endpoint flow from all trust anchors. Attempts: ${anchorErrors.join(' | ')}`
  );
}

async function discoverViaLocalFlow(
  request: FederationDiscoveryRequest,
  options: FederationDiscoveryOptions
): Promise<ResolvedFederationEntity> {
  const fetcher = options.fetcher!;

  const entityId = toCanonicalEntityId(request.entityId as URL);
  const trustAnchors = request.trustAnchors.map((anchor) => toCanonicalEntityId(anchor as URL));

  const subjectEntityConfig = await fetchEntityConfiguration(request.entityId as URL, fetcher);
  const chains = await buildLocalChains(
    subjectEntityConfig,
    trustAnchors,
    options,
    fetcher,
    new Set([entityId]),
    0
  );

  const selectedChain = chooseBestChain(chains);
  const validated = await resolveStatementsFromChain(selectedChain, trustAnchors, options);

  return buildResolvedFromValidatedChain(
    entityId,
    validated.statements,
    validated.expiresAt,
    validated.trustAnchor
  );
}

function normalizeRequest(request: FederationDiscoveryRequest): FederationDiscoveryRequest {
  const entityId = ensureHttpsEntityId(request.entityId);

  if (request.trustAnchors.length === 0) {
    throw new Error('At least one trust anchor is required');
  }

  const trustAnchors = request.trustAnchors.map(ensureHttpsEntityId);

  return {
    entityId,
    trustAnchors,
  };
}

function toFailure(
  code: FederationError['code'],
  message: string,
  cause?: unknown
): FederationDiscoveryResult {
  return {
    valid: false,
    error: {
      code,
      message,
      cause,
    },
  };
}

async function tryDiscoveryFlows(
  request: FederationDiscoveryRequest,
  options: FederationDiscoveryOptions
): Promise<FederationDiscoveryResult> {
  const strategies = options.discoveryStrategy ?? [DiscoveryStrategy.federation_fetch_endpoint];
  if (strategies.length === 0) {
    throw new Error('At least one discovery strategy is required');
  }

  const flowErrors: Array<{ strategy: DiscoveryStrategy; error: Error }> = [];

  for (const strategy of strategies) {
    try {
      let resolved: ResolvedFederationEntity;
      if (strategy === DiscoveryStrategy.issuer_endpoint) {
        resolved = await discoverViaLocalFlow(request, options);
      } else if (strategy === DiscoveryStrategy.federation_fetch_endpoint) {
        resolved = await discoverViaFetchEndpointFlow(request, options);
      } else {
        throw new Error(`Unsupported discovery strategy: ${String(strategy)}`);
      }

      return {
        valid: true,
        data: resolved,
      };
    } catch (error) {
      flowErrors.push({
        strategy,
        error: error instanceof Error ? error : new Error(String(error)),
      });
    }
  }

  throw new DiscoveryAggregateError(flowErrors);
}

function classifyErrorMessage(normalized: string): FederationError['code'] | undefined {
  if (
    normalized.includes('schema validation failed') ||
    normalized.includes('federation_list_endpoint') ||
    normalized.includes('not a json array')
  ) {
    return 'SchemaValidationFailed';
  }

  if (normalized.includes('content-type') && normalized.includes('entity list')) {
    return 'InvalidInput';
  }

  if (
    normalized.includes('enotfound') ||
    normalized.includes('connrefused') ||
    normalized.includes('timeout') ||
    normalized.includes('fetch failed') ||
    normalized.includes('failed to fetch')
  ) {
    return 'NetworkError';
  }
  if (
    normalized.includes('typ') ||
    normalized.includes('jwt') ||
    normalized.includes('content-type')
  ) {
    return 'InvalidJwtType';
  }
  if (
    normalized.includes('trust') ||
    normalized.includes('chain') ||
    normalized.includes('constraint')
  ) {
    return 'TrustChainInvalid';
  }
  if (normalized.includes('http')) {
    return 'NetworkError';
  }
  if (normalized.includes('strategy')) {
    return 'Unsupported';
  }
  return undefined;
}

function classifyDiscoveryError(error: unknown): FederationDiscoveryResult {
  const message = error instanceof Error ? error.message : 'Unknown discovery error';
  const normalized = message.toLowerCase();

  if (error instanceof DiscoveryAggregateError) {
    for (const { error: flowError } of error.flowErrors) {
      const code = classifyErrorMessage(flowError.message.toLowerCase());
      if (code) {
        return toFailure(code, message, error);
      }
    }

    return toFailure('InvalidInput', message, error);
  }

  const code = classifyErrorMessage(normalized);
  return toFailure(code ?? 'InvalidInput', message, error);
}

function getListEndpoint(entityConfig: ParsedEntityStatement): string {
  const metadata = entityConfig.payload.metadata;
  const federationEntity = metadata?.federation_entity;
  const endpoint = federationEntity?.federation_list_endpoint;

  if (typeof endpoint !== 'string') {
    throw new TypeError(`Missing federation_list_endpoint in ${entityConfig.payload.sub}`);
  }

  return endpoint;
}

function toEntitiesFailure(
  code: FederationError['code'],
  message: string,
  cause?: unknown
): DiscoverEntitiesResult {
  return {
    valid: false,
    error: {
      code,
      message,
      cause,
    },
  };
}

function classifyEntitiesError(error: unknown): DiscoverEntitiesResult {
  const message = error instanceof Error ? error.message : 'Unknown discovery error';
  const normalized = message.toLowerCase();
  const code = classifyErrorMessage(normalized);
  return toEntitiesFailure(code ?? 'InvalidInput', message, error);
}

function normalizeEntitiesRequest(request: DiscoverEntitiesRequest): { trustAnchorUrls: URL[] } {
  if (request.trustAnchors.length === 0) {
    throw new Error('At least one trust anchor is required');
  }

  const trustAnchorUrls = request.trustAnchors.map(ensureHttpsEntityId);
  return { trustAnchorUrls };
}

async function fetchEntityList(trustAnchorUrl: URL, fetcher: typeof fetch): Promise<URL[]> {
  const trustAnchorConfig = await fetchEntityConfiguration(trustAnchorUrl, fetcher);
  const listEndpoint = getListEndpoint(trustAnchorConfig);

  const url = new URL(listEndpoint);

  const response = await fetcher(url.toString());
  if (!response.ok) {
    const endpointError = await parseEndpointError(response);
    const detail = endpointError ? `: ${endpointError}` : '';
    throw new Error(`Failed to fetch entity list from ${listEndpoint}${detail}`);
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    throw new Error(`Unexpected content-type for entity list from ${listEndpoint}: ${contentType}`);
  }

  const entities: unknown = await response.json();
  if (!Array.isArray(entities) || !entities.every((e) => typeof e === 'string')) {
    throw new Error(`Entity list response from ${listEndpoint} is not a JSON array of strings`);
  }

  return entities.map((entity) => {
    try {
      return ensureHttpsEntityId(entity);
    } catch {
      throw new Error(`Entity list from ${listEndpoint} contains invalid entity URI: ${entity}`);
    }
  });
}

async function collectEntityLists(trustAnchorUrls: URL[], fetcher: typeof fetch): Promise<URL[]> {
  const seen = new Set<string>();
  const collected: URL[] = [];
  const anchorErrors: string[] = [];

  for (const trustAnchorUrl of trustAnchorUrls) {
    try {
      const entities = await fetchEntityList(trustAnchorUrl, fetcher);
      for (const entity of entities) {
        const key = entity.toString();
        if (!seen.has(key)) {
          seen.add(key);
          collected.push(entity);
        }
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      anchorErrors.push(`${toCanonicalEntityId(trustAnchorUrl)} => ${reason}`);
    }
  }

  if (anchorErrors.length > 0) {
    throw new Error(
      `Failed to fetch entity list from trust anchors. Attempts: ${anchorErrors.join(' | ')}`
    );
  }

  return collected;
}

/**
 * Discovers and validates OpenID Federation metadata for a subject entity.
 *
 * By default the function discovers the subject entity from configured trust anchors
 * via `federation_fetch_endpoint`, validates entity statements, verifies signatures
 * and temporal claims, then returns a typed success/error envelope.
 *
 * Discovery strategy execution is ordered by `options.discoveryStrategy`.
 * The default strategy is `federation_fetch_endpoint`. Include `issuer_endpoint`
 * to attempt subject-up trust-chain discovery via `authority_hints`.
 *
 * @param requestInput Subject entity and trusted anchor identifiers.
 * @param optionsInput Optional runtime controls for fetch, recursion, and time checks.
 * @returns `FederationDiscoveryResult` with `valid=true` and discovery data, or
 *          `valid=false` and a typed `FederationError`.
 */
export async function discoverFederationEntity(
  requestInput: FederationDiscoveryRequest,
  optionsInput: FederationDiscoveryOptions = {}
): Promise<FederationDiscoveryResult> {
  try {
    const request = normalizeRequest(requestInput);
    const options = normalizeOptions(optionsInput);

    return await tryDiscoveryFlows(request, options);
  } catch (error) {
    return classifyDiscoveryError(error);
  }
}

/**
 * Lists subordinate entities published by one or more trust anchors.
 *
 * For each trust anchor the function fetches its entity configuration,
 * locates the `federation_list_endpoint`, and collects the JSON array of
 * entity identifiers advertised at that endpoint.  Results from all
 * trust anchors are merged into a single deduplicated list.
 *
 * All trust anchors must respond successfully.  If any trust anchor fails
 * the function returns an error envelope that summarises the individual
 * failures.
 *
 * @param requestInput Trust anchor identifiers.
 * @param optionsInput Optional runtime controls for fetch behavior.
 * @returns `DiscoverEntitiesResult` with `valid=true` and a deduplicated array
 *          of entity identifier URLs via `entityUris`, or `valid=false` and a typed
 *          `FederationError`.
 */
export async function discoverEntities(
  requestInput: DiscoverEntitiesRequest,
  optionsInput: FederationDiscoveryOptions = {}
): Promise<DiscoverEntitiesResult> {
  try {
    const { trustAnchorUrls } = normalizeEntitiesRequest(requestInput);
    const options = normalizeOptions(optionsInput);
    const entities = await collectEntityLists(trustAnchorUrls, options.fetcher!);

    return {
      valid: true,
      entityUris: entities,
    };
  } catch (error) {
    return classifyEntitiesError(error);
  }
}
