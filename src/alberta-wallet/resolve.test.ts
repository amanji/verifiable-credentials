import type { SDJWT, VCSDJWT } from '../sdjwt';
import { resolveAlbertaWallet } from './resolve';
import type { AlbertaCredentialIssuer } from './types';
import * as schemaValidator from './schema-validator';

const credentialDefinitionUri = 'https://account.alberta.ca/dts/adhc/assets/adhc-schema-v1.json';
const credentialDisplayDefinitionUri =
  'https://account.alberta.ca/dts/adhc/assets/adhc-display-v1.json';
const credentialDisplayDefinition = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://account.alberta.ca/dts/wallet/card-display-v1.json',
  display_template: 'urn:wallet.alberta.ca:template_v1',
  schema_uri: 'https://example.com/schema',
  card_title: 'Card',
  text_color: '#000000',
  top_left_icon: { uri: 'https://example.com/icon.png' },
  background: { color: '#FFFFFF' },
};

function buildIssuer(configOverrides?: Partial<AlbertaCredentialIssuer>): AlbertaCredentialIssuer {
  return {
    organization_name: 'Alberta Health Services',
    organization_uri: 'https://myhealth.alberta.ca',
    description: 'Issuer',
    information_uri: 'https://www.alberta.ca/mobile-health-card',
    credential_configurations_supported: {
      health_card_v1: {
        typ: 'ADHC',
        description: 'Mobile Health Card',
        credential_issuer: 'https://healthcard.alberta.ca',
        jwks_uri: 'https://healthcard.alberta.ca/.well-known/jwks.json',
        revocation_list_endpoint: 'https://healthcard.alberta.ca/.well-known/revocation-list/',
        revocation_method: 'status-list-jti',
        credential_definition: { uri: credentialDefinitionUri },
        credential_display: { uri: credentialDisplayDefinitionUri },
        proof_type: { type: 'secure-qr-jwt', jwks_uri: 'https://issuer.example.org/jwks' },
        icon: { uri: 'https://healthcard.alberta.ca/icon.png' },
      },
    },
    ...configOverrides,
  };
}

describe('resolveAlbertaWallet', () => {
  beforeEach(() => {
    jest
      .spyOn(schemaValidator, 'isAlbertaCredentialIssuer')
      .mockImplementation((value: unknown) => {
        return Boolean((value as { organization_name?: unknown })?.organization_name);
      });
    jest
      .spyOn(schemaValidator, 'isCredentialDisplayDefinition')
      .mockImplementation((value: unknown) => {
        return Boolean((value as { display_template?: unknown })?.display_template);
      });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('resolves by vct for VCSDJWT', async () => {
    const issuer = buildIssuer();
    const es = {
      metadata: {
        openid_credential_issuer: issuer,
      },
    };

    const sdjwt: VCSDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      vct: 'ADHC',
    };

    const fetcher = jest.fn().mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue(credentialDisplayDefinition),
    });

    const result = await resolveAlbertaWallet({ es, sdjwt, fetcher });

    expect(result.albertaCredentialIssuer).toBe(issuer);
    expect(result.credentialConfiguration.typ).toBe('ADHC');
    expect(result.credentialDisplayDefinition).toEqual(credentialDisplayDefinition);
    expect(fetcher).toHaveBeenCalledWith(credentialDisplayDefinitionUri);
  });

  it('resolves by type claim for plain SDJWT', async () => {
    const issuer = buildIssuer();
    const es = {
      metadata: {
        openid_credential_issuer: issuer,
      },
    };

    const sdjwt: SDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      type: 'ADHC',
    };

    const fetcher = jest.fn().mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue(credentialDisplayDefinition),
    });

    const result = await resolveAlbertaWallet({ es, sdjwt, fetcher });

    expect(result.credentialConfiguration.typ).toBe('ADHC');
    expect(result.credentialDisplayDefinition.display_template).toBe(
      'urn:wallet.alberta.ca:template_v1'
    );
  });

  it('throws when metadata is missing', async () => {
    const sdjwt: SDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      type: 'ADHC',
    };

    await expect(resolveAlbertaWallet({ es: {}, sdjwt })).rejects.toThrow(
      'ES metadata must be an object'
    );
  });

  it('throws when multiple metadata entries match issuer schema', async () => {
    const es = {
      metadata: {
        issuer_a: buildIssuer(),
        issuer_b: buildIssuer(),
      },
    };

    const sdjwt: SDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      type: 'ADHC',
    };

    await expect(resolveAlbertaWallet({ es, sdjwt })).rejects.toThrow(
      'Multiple metadata entity entries match AlbertaCredentialIssuer schema'
    );
  });

  it('resolves when token vct differs in casing from cfg.typ (case-insensitive match)', async () => {
    const issuer = buildIssuer();
    const es = {
      metadata: {
        openid_credential_issuer: issuer,
      },
    };

    const sdjwt: VCSDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      vct: 'adhc',
    };

    const fetcher = jest.fn().mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue(credentialDisplayDefinition),
    });

    const result = await resolveAlbertaWallet({ es, sdjwt, fetcher });

    expect(result.albertaCredentialIssuer).toBe(issuer);
    expect(result.credentialConfiguration.typ).toBe('ADHC');
    expect(result.credentialDisplayDefinition).toEqual(credentialDisplayDefinition);
    expect(fetcher).toHaveBeenCalledWith(credentialDisplayDefinitionUri);
  });

  it('does not match a configuration where cfg.typ is undefined, throws error', async () => {
    const issuer = buildIssuer({
      credential_configurations_supported: {
        health_card_v1: {
          typ: undefined as unknown as string,
          description: 'Mobile Health Card',
          credential_issuer: 'https://healthcard.alberta.ca',
          jwks_uri: 'https://healthcard.alberta.ca/.well-known/jwks.json',
          revocation_list_endpoint: 'https://healthcard.alberta.ca/.well-known/revocation-list/',
          revocation_method: 'status-list-jti',
          credential_definition: { uri: credentialDefinitionUri },
          credential_display: { uri: credentialDisplayDefinitionUri },
          proof_type: { type: 'secure-qr-jwt', jwks_uri: 'https://issuer.example.org/jwks' },
          icon: { uri: 'https://healthcard.alberta.ca/icon.png' },
        },
      },
    });
    const es = { metadata: { openid_credential_issuer: issuer } };
    const sdjwt: VCSDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      vct: 'ADHC',
    };

    await expect(resolveAlbertaWallet({ es, sdjwt })).rejects.toThrow(
      "No credential configuration found for typ 'ADHC' and credential_issuer 'https://healthcard.alberta.ca'"
    );
  });

  it('does not match a configuration where cfg.typ is null, throws error', async () => {
    const issuer = buildIssuer({
      credential_configurations_supported: {
        health_card_v1: {
          typ: null as unknown as string,
          description: 'Mobile Health Card',
          credential_issuer: 'https://healthcard.alberta.ca',
          jwks_uri: 'https://healthcard.alberta.ca/.well-known/jwks.json',
          revocation_list_endpoint: 'https://healthcard.alberta.ca/.well-known/revocation-list/',
          revocation_method: 'status-list-jti',
          credential_definition: { uri: credentialDefinitionUri },
          credential_display: { uri: credentialDisplayDefinitionUri },
          proof_type: { type: 'secure-qr-jwt', jwks_uri: 'https://issuer.example.org/jwks' },
          icon: { uri: 'https://healthcard.alberta.ca/icon.png' },
        },
      },
    });
    const es = { metadata: { openid_credential_issuer: issuer } };
    const sdjwt: VCSDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      vct: 'ADHC',
    };

    await expect(resolveAlbertaWallet({ es, sdjwt })).rejects.toThrow(
      "No credential configuration found for typ 'ADHC' and credential_issuer 'https://healthcard.alberta.ca'"
    );
  });

  it('skips configurations with null typ and matches the one with a valid typ', async () => {
    const issuer = buildIssuer({
      credential_configurations_supported: {
        health_card_null_typ: {
          typ: null as unknown as string,
          description: 'Invalid config',
          credential_issuer: 'https://healthcard.alberta.ca',
          jwks_uri: 'https://healthcard.alberta.ca/.well-known/jwks.json',
          revocation_list_endpoint: 'https://healthcard.alberta.ca/.well-known/revocation-list/',
          revocation_method: 'status-list-jti',
          credential_definition: { uri: credentialDefinitionUri },
          credential_display: { uri: credentialDisplayDefinitionUri },
          proof_type: { type: 'secure-qr-jwt', jwks_uri: 'https://issuer.example.org/jwks' },
          icon: { uri: 'https://healthcard.alberta.ca/icon.png' },
        },
        health_card_v1: {
          typ: 'ADHC',
          description: 'Mobile Health Card',
          credential_issuer: 'https://healthcard.alberta.ca',
          jwks_uri: 'https://healthcard.alberta.ca/.well-known/jwks.json',
          revocation_list_endpoint: 'https://healthcard.alberta.ca/.well-known/revocation-list/',
          revocation_method: 'status-list-jti',
          credential_definition: { uri: credentialDefinitionUri },
          credential_display: { uri: credentialDisplayDefinitionUri },
          proof_type: { type: 'secure-qr-jwt', jwks_uri: 'https://issuer.example.org/jwks' },
          icon: { uri: 'https://healthcard.alberta.ca/icon.png' },
        },
      },
    });
    const es = { metadata: { openid_credential_issuer: issuer } };
    const sdjwt: VCSDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      vct: 'ADHC',
    };

    const fetcher = jest.fn().mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue(credentialDisplayDefinition),
    });

    const result = await resolveAlbertaWallet({ es, sdjwt, fetcher });

    expect(result.credentialConfiguration.typ).toBe('ADHC');
    expect(result.credentialDisplayDefinition).toEqual(credentialDisplayDefinition);
  });

  it('throws when no credential configuration matches token type', async () => {
    const issuer = buildIssuer();
    const es = {
      metadata: {
        openid_credential_issuer: issuer,
      },
    };

    const sdjwt: SDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      type: 'UNKNOWN',
    };

    await expect(resolveAlbertaWallet({ es, sdjwt })).rejects.toThrow(
      "No credential configuration found for typ 'UNKNOWN' and credential_issuer 'https://healthcard.alberta.ca'"
    );
  });

  it('throws when credential definition fetch fails', async () => {
    const issuer = buildIssuer();
    const es = {
      metadata: {
        openid_credential_issuer: issuer,
      },
    };

    const sdjwt: SDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      type: 'ADHC',
    };

    const fetcher = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });

    await expect(resolveAlbertaWallet({ es, sdjwt, fetcher })).rejects.toThrow(
      `Failed to fetch credential definition from '${credentialDefinitionUri}' (status 404)`
    );
  });

  it('throws when credential display fetch fails', async () => {
    const issuer = buildIssuer();
    const es = {
      metadata: {
        openid_credential_issuer: issuer,
      },
    };

    const sdjwt: SDJWT = {
      iss: 'https://healthcard.alberta.ca',
      iat: 1700000000,
      type: 'ADHC',
    };

    const fetcher = jest
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({
          $schema: 'https://account.alberta.ca/dts/schemas/sd-jwt-v1.json',
          iss: 'https://healthcard.alberta.ca',
          iat: 1700000000,
          type: 'ADHC',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

    await expect(resolveAlbertaWallet({ es, sdjwt, fetcher })).rejects.toThrow(
      `Failed to fetch credential display definition from '${credentialDisplayDefinitionUri}' (status 404)`
    );

    expect(fetcher).toHaveBeenNthCalledWith(1, credentialDefinitionUri);
    expect(fetcher).toHaveBeenNthCalledWith(2, credentialDisplayDefinitionUri);
  });
});
