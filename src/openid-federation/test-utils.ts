import * as jose from 'jose';

export interface LocalChainFixture {
  leafEntityId: string;
  trustAnchorId: string;
  now: number;
  leafPublicJwk: JsonWebKey;
  taPublicJwk: JsonWebKey;
  leafEntityConfigJwt: string;
  subordinateStatementJwt: string;
  trustAnchorEntityConfigJwt: string;
  listEntities: string[];
}

export async function createLocalChainFixture(params?: {
  leafEntityId?: string;
  trustAnchorId?: string;
  now?: number;
  subordinateSigner?: CryptoKey;
  overrideLeafPayload?: Record<string, unknown>;
  overrideSubordinatePayload?: Record<string, unknown>;
  overrideTrustAnchorPayload?: Record<string, unknown>;
  leafTyp?: string;
  subordinateTyp?: string;
  listEntities?: string[];
}): Promise<LocalChainFixture> {
  const leafEntityId = params?.leafEntityId ?? 'https://leaf.example.org';
  const trustAnchorId = params?.trustAnchorId ?? 'https://ta.example.org';
  const now = params?.now ?? Math.trunc(Date.now() / 1000);

  const leafPair = await jose.generateKeyPair('RS256');
  const trustAnchorPair = await jose.generateKeyPair('RS256');

  const leafPublicJwk = await jose.exportJWK(leafPair.publicKey);
  const taPublicJwk = await jose.exportJWK(trustAnchorPair.publicKey);
  leafPublicJwk.kid = 'leaf-kid';
  taPublicJwk.kid = 'ta-kid';

  const leafPayload: Record<string, unknown> = {
    iss: leafEntityId,
    sub: leafEntityId,
    iat: now,
    exp: now + 3600,
    authority_hints: [trustAnchorId],
    jwks: { keys: [leafPublicJwk] },
    metadata: {
      openid_relying_party: {
        contacts: ['ops@leaf.example.org'],
        grant_types: ['authorization_code', 'refresh_token'],
      },
    },
  };
  if (params?.overrideLeafPayload) {
    Object.assign(leafPayload, params.overrideLeafPayload);
  }

  const subordinatePayload: Record<string, unknown> = {
    iss: trustAnchorId,
    sub: leafEntityId,
    iat: now,
    exp: now + 3600,
    jwks: { keys: [taPublicJwk] },
    metadata: {
      openid_relying_party: {
        policy_uri: 'https://ta.example.org/policy',
      },
    },
  };
  if (params?.overrideSubordinatePayload) {
    Object.assign(subordinatePayload, params.overrideSubordinatePayload);
  }

  const trustAnchorPayload: Record<string, unknown> = {
    iss: trustAnchorId,
    sub: trustAnchorId,
    iat: now,
    exp: now + 3600,
    jwks: { keys: [taPublicJwk] },
    metadata: {
      federation_entity: {
        federation_fetch_endpoint: `${trustAnchorId}/fetch`,
        federation_list_endpoint: `${trustAnchorId}/list`,
      },
    },
  };
  if (params?.overrideTrustAnchorPayload) {
    Object.assign(trustAnchorPayload, params.overrideTrustAnchorPayload);
  }

  const leafEntityConfigJwt = await new jose.SignJWT(leafPayload)
    .setProtectedHeader({
      alg: 'RS256',
      typ: params?.leafTyp ?? 'entity-statement+jwt',
      kid: 'leaf-kid',
    })
    .sign(leafPair.privateKey);

  const subordinateSigner = params?.subordinateSigner ?? trustAnchorPair.privateKey;
  const subordinateStatementJwt = await new jose.SignJWT(subordinatePayload)
    .setProtectedHeader({
      alg: 'RS256',
      typ: params?.subordinateTyp ?? 'entity-statement+jwt',
      kid: 'ta-kid',
    })
    .sign(subordinateSigner);

  const trustAnchorEntityConfigJwt = await new jose.SignJWT(trustAnchorPayload)
    .setProtectedHeader({ alg: 'RS256', typ: 'entity-statement+jwt', kid: 'ta-kid' })
    .sign(trustAnchorPair.privateKey);

  const listEntities = params?.listEntities ?? [leafEntityId];

  return {
    leafEntityId,
    trustAnchorId,
    now,
    leafPublicJwk,
    taPublicJwk,
    leafEntityConfigJwt,
    subordinateStatementJwt,
    trustAnchorEntityConfigJwt,
    listEntities,
  };
}

export function makeJsonHeaders(contentType: string): Headers {
  return new Headers({ 'content-type': contentType });
}

export function makeJwtResponse(body: string): Response {
  return {
    ok: true,
    headers: makeJsonHeaders('application/entity-statement+jwt'),
    text: () => Promise.resolve(body),
    json: () => Promise.resolve({}),
    status: 200,
  } as unknown as Response;
}

function getRequestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }

  if (input instanceof URL) {
    return input.toString();
  }

  return input.url;
}

export function makeJsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    headers: makeJsonHeaders('application/json'),
    text: () => Promise.resolve(JSON.stringify(body)),
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

export function makeLocalDiscoveryFetcher(
  fixture: LocalChainFixture,
  overrides?: {
    leafResponse?: Response;
    trustAnchorResponse?: Response;
    subordinateResponse?: Response;
    listResponse?: Response;
    fallbackResponse?: Response;
  }
): typeof fetch {
  return (input: RequestInfo | URL) => {
    const url = getRequestUrl(input);

    if (url === `${fixture.leafEntityId}/.well-known/openid-federation`) {
      return Promise.resolve(
        overrides?.leafResponse ?? makeJwtResponse(fixture.leafEntityConfigJwt)
      );
    }

    if (url === `${fixture.trustAnchorId}/.well-known/openid-federation`) {
      return Promise.resolve(
        overrides?.trustAnchorResponse ?? makeJwtResponse(fixture.trustAnchorEntityConfigJwt)
      );
    }

    if (url.startsWith(`${fixture.trustAnchorId}/fetch`)) {
      return Promise.resolve(
        overrides?.subordinateResponse ?? makeJwtResponse(fixture.subordinateStatementJwt)
      );
    }

    if (url.startsWith(`${fixture.trustAnchorId}/list`)) {
      return Promise.resolve(overrides?.listResponse ?? makeJsonResponse(fixture.listEntities));
    }

    return Promise.resolve(
      overrides?.fallbackResponse ??
        ({
          ok: false,
          status: 404,
          headers: makeJsonHeaders('application/json'),
          text: () => Promise.resolve(''),
          json: () => Promise.resolve({ error: 'not_found', error_description: 'not found' }),
        } as unknown as Response)
    );
  };
}
