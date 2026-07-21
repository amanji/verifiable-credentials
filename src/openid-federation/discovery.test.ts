import { discoverFederationEntity, discoverEntities } from './discovery';
import {
  createLocalChainFixture,
  makeJsonHeaders,
  makeJsonResponse,
  makeJwtResponse,
  makeLocalDiscoveryFetcher,
} from './test-utils';
import { DiscoveryStrategy } from './types';

describe('OpenID Federation discovery', () => {
  it('resolves local trust chain when issuer_endpoint strategy is configured', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: new URL(fixture.leafEntityId),
        trustAnchors: [fixture.trustAnchorId],
      },
      {
        fetcher,
        discoveryStrategy: [DiscoveryStrategy.issuer_endpoint],
      }
    );

    expect(result.valid).toBe(true);
    expect(result.data?.trustAnchor).toBe(fixture.trustAnchorId);
    expect(result.data?.metadata.openid_relying_party.contacts).toEqual(['ops@leaf.example.org']);
    expect(result.data?.metadata.openid_relying_party.grant_types).toEqual([
      'authorization_code',
      'refresh_token',
    ]);
    expect(result.data?.metadata.openid_relying_party.policy_uri).toBeUndefined();
  });

  it('resolves trust chain via federation_fetch_endpoint flow', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: new URL(fixture.leafEntityId),
        trustAnchors: [fixture.trustAnchorId],
      },
      {
        fetcher,
      }
    );

    expect(result.valid).toBe(true);
    expect(result.data?.trustAnchor).toBe(fixture.trustAnchorId);
    expect(result.data?.metadata.openid_relying_party.policy_uri).toBe(
      'https://ta.example.org/policy'
    );
    expect(result.data?.metadata.openid_relying_party.contacts).toBeUndefined();
    expect(result.data?.metadata.openid_relying_party.grant_types).toBeUndefined();
    expect(result.data?.metadata.openid_relying_party.token_endpoint_auth_method).toBeUndefined();
  });

  it('rejects invalid trust chains', async () => {
    const wrongSigner = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );

    const fixture = await createLocalChainFixture({ subordinateSigner: wrongSigner.privateKey });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      {
        fetcher,
      }
    );

    expect(result.valid).toBe(false);
    expect(result.error?.message).toBeDefined();
  });

  it('maps non-https entity IDs to NetworkError under current classifier', async () => {
    const result = await discoverFederationEntity({
      entityId: 'http://leaf.example.org',
      trustAnchors: ['https://ta.example.org'],
    });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('NetworkError');
  });

  it('maps empty trust anchor input to TrustChainInvalid under current classifier', async () => {
    const result = await discoverFederationEntity({
      entityId: 'https://leaf.example.org',
      trustAnchors: [],
    });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('TrustChainInvalid');
  });

  it('maps non-JWT content-type to InvalidJwtType under current classifier', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture, {
      leafResponse: {
        ok: true,
        status: 200,
        headers: makeJsonHeaders('application/json'),
        text: () => Promise.resolve('{}'),
        json: () => Promise.resolve({}),
      } as unknown as Response,
      subordinateResponse: {
        ok: true,
        status: 200,
        headers: makeJsonHeaders('application/json'),
        text: () => Promise.resolve('{}'),
        json: () => Promise.resolve({}),
      } as unknown as Response,
    });

    const result = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('InvalidJwtType');
  });

  it('returns SchemaValidationFailed for invalid entity statement payloads', async () => {
    const fixture = await createLocalChainFixture({
      overrideLeafPayload: {
        jwks: undefined,
      },
      overrideSubordinatePayload: {
        jwks: undefined,
      },
    });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('SchemaValidationFailed');
  });

  it('returns InvalidJwtType for non entity-statement typ header', async () => {
    const fixture = await createLocalChainFixture({ leafTyp: 'JWT', subordinateTyp: 'JWT' });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('InvalidJwtType');
  });

  it('uses federation_fetch_endpoint flow by default', async () => {
    const fixture = await createLocalChainFixture({
      overrideLeafPayload: {
        authority_hints: [],
      },
    });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: new URL(fixture.leafEntityId),
        trustAnchors: [fixture.trustAnchorId],
      },
      { fetcher }
    );

    expect(result.valid).toBe(true);
    // Subject and trust anchor identifiers must be correct.
    expect(result.data?.subject).toBe(fixture.leafEntityId);
    expect(result.data?.trustAnchor).toBe(fixture.trustAnchorId);
    // In the fetch-endpoint flow the first chain element is the subordinate
    // statement issued by the trust anchor, so metadata reflects the TA's
    // view of the leaf (policy_uri) rather than the leaf's self-declared fields.
    expect(result.data?.metadata.openid_relying_party?.policy_uri).toBe(
      'https://ta.example.org/policy'
    );
    // trustChain contains exactly the subordinate statement and the trust anchor
    // entity configuration (two-element chain).
    expect(result.data?.trustChain).toHaveLength(2);
  });

  it('returns TrustChainInvalid when no chain can be built to trust anchors', async () => {
    const fixture = await createLocalChainFixture({
      overrideLeafPayload: {
        authority_hints: ['https://other-anchor.example.org'],
      },
      overrideTrustAnchorPayload: {
        metadata: {
          federation_entity: {},
        },
      },
    });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('TrustChainInvalid');
  });

  it('falls back to federation_fetch_endpoint flow when issuer_endpoint strategy cannot resolve a chain', async () => {
    const fixture = await createLocalChainFixture({
      overrideLeafPayload: {
        authority_hints: [],
      },
    });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverFederationEntity(
      {
        entityId: new URL(fixture.leafEntityId),
        trustAnchors: [fixture.trustAnchorId],
      },
      {
        fetcher,
        discoveryStrategy: [
          DiscoveryStrategy.issuer_endpoint,
          DiscoveryStrategy.federation_fetch_endpoint,
        ],
      }
    );

    expect(result.valid).toBe(true);
    expect(result.data?.subject).toBe(fixture.leafEntityId);
    expect(result.data?.trustAnchor).toBe(fixture.trustAnchorId);
    expect(result.data?.metadata.openid_relying_party?.policy_uri).toBe(
      'https://ta.example.org/policy'
    );
    expect(result.data?.trustChain).toHaveLength(2);
  });

  it('respects strategy order when both issuer_endpoint and federation_fetch_endpoint are configured', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const localFirst = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      {
        fetcher,
        discoveryStrategy: [
          DiscoveryStrategy.issuer_endpoint,
          DiscoveryStrategy.federation_fetch_endpoint,
        ],
      }
    );

    expect(localFirst.valid).toBe(true);
    expect(localFirst.data?.metadata.openid_relying_party?.contacts).toEqual([
      'ops@leaf.example.org',
    ]);
    expect(localFirst.data?.metadata.openid_relying_party?.policy_uri).toBeUndefined();

    const fetchFirst = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      {
        fetcher,
        discoveryStrategy: [
          DiscoveryStrategy.federation_fetch_endpoint,
          DiscoveryStrategy.issuer_endpoint,
        ],
      }
    );

    expect(fetchFirst.valid).toBe(true);
    expect(fetchFirst.data?.metadata.openid_relying_party?.policy_uri).toBe(
      'https://ta.example.org/policy'
    );
    expect(fetchFirst.data?.metadata.openid_relying_party?.contacts).toBeUndefined();
  });

  it('does not misclassify Missing federation_fetch_endpoint as NetworkError', async () => {
    // Trust anchor has no federation_fetch_endpoint, so the fetch endpoint flow will fail
    // with "Missing federation_fetch_endpoint in ..." — which must NOT be classified as NetworkError.
    const fixture = await createLocalChainFixture({
      overrideTrustAnchorPayload: {
        metadata: {
          federation_entity: {}, // no federation_fetch_endpoint
        },
      },
    });

    // Use a fetcher that rejects the leaf config request with an unrecognized error so the
    // local flow fails with a message that has no recognizable error code, allowing the fetch
    // endpoint flow's classification to determine the final result.
    const fetcher = (input: RequestInfo | URL): Promise<Response> => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url === `${fixture.leafEntityId}/.well-known/openid-federation`) {
        return Promise.reject(new Error('Request rejected by policy'));
      }

      if (url === `${fixture.trustAnchorId}/.well-known/openid-federation`) {
        return Promise.resolve(makeJwtResponse(fixture.trustAnchorEntityConfigJwt));
      }

      return Promise.resolve({
        ok: false,
        status: 404,
        headers: makeJsonHeaders('application/json'),
        text: () => Promise.resolve(''),
        json: () => Promise.resolve({ error: 'not_found', error_description: 'not found' }),
      } as unknown as Response);
    };

    const result = await discoverFederationEntity(
      {
        entityId: fixture.leafEntityId,
        trustAnchors: [fixture.trustAnchorId],
      },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error?.code).not.toBe('NetworkError');
  });
});

describe('discoverEntities', () => {
  it('returns entity list from a single trust anchor', async () => {
    const fixture = await createLocalChainFixture({
      listEntities: ['https://issuer-a.example.org', 'https://issuer-b.example.org'],
    });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverEntities({ trustAnchors: [fixture.trustAnchorId] }, { fetcher });

    expect(result.valid).toBe(true);
    expect(result.entityUris).toEqual([
      new URL('https://issuer-a.example.org'),
      new URL('https://issuer-b.example.org'),
    ]);
  });

  it('deduplicates entities across multiple trust anchors', async () => {
    const fixtureA = await createLocalChainFixture({
      trustAnchorId: 'https://ta-a.example.org',
      listEntities: ['https://issuer-1.example.org', 'https://issuer-2.example.org'],
    });
    const fixtureB = await createLocalChainFixture({
      trustAnchorId: 'https://ta-b.example.org',
      listEntities: ['https://issuer-2.example.org', 'https://issuer-3.example.org'],
    });

    const fetcher = (input: RequestInfo | URL): Promise<Response> => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url === 'https://ta-a.example.org/.well-known/openid-federation') {
        return Promise.resolve(makeJwtResponse(fixtureA.trustAnchorEntityConfigJwt));
      }
      if (url.startsWith('https://ta-a.example.org/list')) {
        return Promise.resolve(makeJsonResponse(fixtureA.listEntities));
      }
      if (url === 'https://ta-b.example.org/.well-known/openid-federation') {
        return Promise.resolve(makeJwtResponse(fixtureB.trustAnchorEntityConfigJwt));
      }
      if (url.startsWith('https://ta-b.example.org/list')) {
        return Promise.resolve(makeJsonResponse(fixtureB.listEntities));
      }

      return Promise.resolve({
        ok: false,
        status: 404,
        headers: makeJsonHeaders('application/json'),
        text: () => Promise.resolve(''),
        json: () => Promise.resolve({ error: 'not_found', error_description: 'not found' }),
      } as unknown as Response);
    };

    const result = await discoverEntities(
      { trustAnchors: ['https://ta-a.example.org', 'https://ta-b.example.org'] },
      { fetcher }
    );

    expect(result.valid).toBe(true);
    expect(result.entityUris).toHaveLength(3);
    expect(result.entityUris!.map((u) => u.toString())).toContain('https://issuer-1.example.org/');
    expect(result.entityUris!.map((u) => u.toString())).toContain('https://issuer-2.example.org/');
    expect(result.entityUris!.map((u) => u.toString())).toContain('https://issuer-3.example.org/');
  });

  it('returns SchemaValidationFailed when trust anchor has no federation_list_endpoint', async () => {
    const fixture = await createLocalChainFixture({
      overrideTrustAnchorPayload: {
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: 'https://ta.example.org/fetch',
            // no federation_list_endpoint
          },
        },
      },
    });
    const fetcher = makeLocalDiscoveryFetcher(fixture);

    const result = await discoverEntities({ trustAnchors: [fixture.trustAnchorId] }, { fetcher });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('SchemaValidationFailed');
    expect(result.error?.message).toContain('federation_list_endpoint');
  });

  it('returns NetworkError when all trust anchors fail with network errors', async () => {
    const fetcher = (): Promise<Response> => {
      return Promise.reject(new Error('fetch failed'));
    };

    const result = await discoverEntities(
      { trustAnchors: ['https://ta.example.org'] },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error?.code).toBe('NetworkError');
  });

  it('returns error for empty trust anchors array', async () => {
    const result = await discoverEntities({ trustAnchors: [] });

    expect(result.valid).toBe(false);
    expect(result.error?.message).toContain('At least one trust anchor is required');
  });

  it('returns InvalidInput when list endpoint returns non-JSON content-type', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture, {
      listResponse: {
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: () => Promise.resolve('<html></html>'),
        json: () => Promise.resolve({}),
      } as unknown as Response,
    });

    const result = await discoverEntities({ trustAnchors: [fixture.trustAnchorId] }, { fetcher });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('InvalidInput');
    expect(result.error?.message).toContain('content-type');
  });

  it('returns SchemaValidationFailed when list endpoint returns non-array response', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture, {
      listResponse: makeJsonResponse({ entities: ['https://issuer.example.org'] }),
    });

    const result = await discoverEntities({ trustAnchors: [fixture.trustAnchorId] }, { fetcher });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('SchemaValidationFailed');
    expect(result.error?.message).toContain('not a JSON array of strings');
  });

  it('returns error when entity list contains invalid URIs', async () => {
    const fixture = await createLocalChainFixture();
    const fetcher = makeLocalDiscoveryFetcher(fixture, {
      listResponse: makeJsonResponse(['not-a-url', 'https://valid.example.org']),
    });

    const result = await discoverEntities({ trustAnchors: [fixture.trustAnchorId] }, { fetcher });

    expect(result.valid).toBe(false);
    expect(result.error?.message).toContain('invalid entity URI');
    expect(result.error?.message).toContain('not-a-url');
  });

  it('returns error with partial trust anchor failures even when some succeed', async () => {
    const fixture = await createLocalChainFixture({
      listEntities: ['https://issuer.example.org'],
    });

    const fetcher = (input: RequestInfo | URL): Promise<Response> => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url === `${fixture.trustAnchorId}/.well-known/openid-federation`) {
        return Promise.resolve(makeJwtResponse(fixture.trustAnchorEntityConfigJwt));
      }
      if (url.startsWith(`${fixture.trustAnchorId}/list`)) {
        return Promise.resolve(makeJsonResponse(fixture.listEntities));
      }

      // Second trust anchor fails
      if (url === 'https://bad-ta.example.org/.well-known/openid-federation') {
        return Promise.reject(new Error('fetch failed'));
      }

      return Promise.resolve({
        ok: false,
        status: 404,
        headers: makeJsonHeaders('application/json'),
        text: () => Promise.resolve(''),
        json: () => Promise.resolve({ error: 'not_found', error_description: 'not found' }),
      } as unknown as Response);
    };

    const result = await discoverEntities(
      { trustAnchors: [fixture.trustAnchorId, 'https://bad-ta.example.org'] },
      { fetcher }
    );

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error?.message).toContain('Failed to fetch entity list from trust anchors');
  });
});
