import type { SDJWT, VCSDJWT } from '../sdjwt';
import type {
  AlbertaCredentialIssuer,
  CredentialConfiguration,
  CredentialDefinition,
  CredentialDisplayDefinition,
  UriRef,
} from './types';
import type { ValidateFunction } from 'ajv';
import validateAlbertaCredentialIssuerSchema from './compiled/validate-alberta-credential-issuer.js';
import validateCredentialDisplaySchema from './compiled/validate-credential-display.js';
import { isAlbertaCredentialIssuer, isCredentialDisplayDefinition } from './schema-validator';

export interface ResolveAlbertaWalletRequest<TSDJWT extends { iss: string } = { iss: string }> {
  /** Entity statement-like object containing `metadata`. */
  es: unknown;
  /** Decoded SD-JWT/VCSDJWT payload used for matching. */
  sdjwt: TSDJWT;
  /** Optional fetch implementation for retrieving remote card display templates. */
  fetcher?: typeof fetch;
}

export interface ResolveAlbertaWalletResult<
  TES = unknown,
  TSDJWT extends { iss: string } = { iss: string },
> {
  /** Original input entity statement object. */
  es: TES;
  /** Original input SD-JWT payload. */
  sdjwt: TSDJWT;
  /** Schema-validated issuer metadata entry selected from entity statement metadata. */
  albertaCredentialIssuer: AlbertaCredentialIssuer;
  /** Credential configuration selected by issuer + type matching rules. */
  credentialConfiguration: CredentialConfiguration;
  /** Resolved credential definition fetched from the selected credential configuration URI. */
  credentialDefinition: CredentialDefinition;
  /** Resolved credential display definition fetched from the selected credential configuration URI. */
  credentialDisplayDefinition: CredentialDisplayDefinition;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Scans entity statement metadata entries and returns the single issuer entry that validates
 * against the Alberta Credential Issuer schema.
 */
function extractIssuerFromMetadataMap(metadata: Record<string, unknown>): AlbertaCredentialIssuer {
  const matches: AlbertaCredentialIssuer[] = [];
  const invalidKeys: string[] = [];

  for (const [key, metadataEntry] of Object.entries(metadata)) {
    if (isAlbertaCredentialIssuer(metadataEntry)) {
      matches.push(metadataEntry);
    } else if (isRecord(metadataEntry)) {
      invalidKeys.push(key);
      validateAlbertaCredentialIssuerSchema(metadataEntry);
      console.warn(
        `[resolve] Metadata key '${key}' failed AlbertaCredentialIssuer schema validation:`,
        (validateAlbertaCredentialIssuerSchema as unknown as ValidateFunction).errors
      );
    }
  }

  if (matches.length > 1) {
    throw new Error('Multiple metadata entity entries match AlbertaCredentialIssuer schema');
  }

  if (matches.length === 0) {
    if (invalidKeys.length > 0) {
      throw new Error(
        `No metadata entry matched the AlbertaCredentialIssuer schema. The following keys were present but failed schema validation: ${invalidKeys.join(', ')}`
      );
    }
    throw new Error('No AlbertaCredentialIssuer entry found in ES metadata');
  }

  return matches[0];
}

function extractAlbertaCredentialIssuer(es: unknown): AlbertaCredentialIssuer {
  if (!isRecord(es)) {
    throw new Error('ES must be an object containing metadata');
  }

  const metadata = es.metadata;
  if (!isRecord(metadata)) {
    throw new Error('ES metadata must be an object');
  }

  return extractIssuerFromMetadataMap(metadata);
}

function isVCSDJWT(token: SDJWT): token is VCSDJWT {
  return typeof (token as VCSDJWT).vct === 'string';
}

/**
 * Resolves credential typ from plain SD-JWT `type` claim.
 */
function resolveTypFromSDJWTTypeClaim(token: SDJWT): string {
  const typeClaim = token.type;

  if (typeof typeClaim === 'string' && typeClaim.length > 0) {
    return typeClaim;
  }

  throw new Error("SD-JWT token has no vct; expected 'type' claim as a non-empty string");
}

function resolveCredentialType(token: SDJWT): string {
  if (isVCSDJWT(token)) {
    return token.vct;
  }

  return resolveTypFromSDJWTTypeClaim(token);
}

function selectMatchingConfiguration(
  issuer: AlbertaCredentialIssuer,
  sdjwtIss: string,
  credentialTyp: string
): CredentialConfiguration {
  const configs = Object.values(issuer.credential_configurations_supported);

  const issuerMatches = configs.filter((cfg) => cfg.credential_issuer === sdjwtIss);
  if (issuerMatches.length === 0) {
    throw new Error(`No credential configuration found for credential_issuer '${sdjwtIss}'`);
  }
  const typMatch = issuerMatches.find(
    (cfg) => cfg.typ?.toLowerCase() === credentialTyp?.toLowerCase()
  );
  if (!typMatch) {
    throw new Error(
      `No credential configuration found for typ '${credentialTyp}' and credential_issuer '${sdjwtIss}'`
    );
  }

  return typMatch;
}

async function fetchCredentialDefinition(
  definitionRef: UriRef,
  fetcher?: typeof fetch
): Promise<CredentialDefinition> {
  const fetchFn = fetcher ?? globalThis.fetch;
  if (typeof fetchFn !== 'function') {
    throw new TypeError('No fetch implementation available to resolve credential definition');
  }

  const response = await fetchFn(definitionRef.uri);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch credential definition from '${definitionRef.uri}' (status ${response.status})`
    );
  }

  const payload: unknown = await response.json();
  return payload as CredentialDefinition;
}

async function fetchCredentialDisplayDefinition(
  displayRef: UriRef,
  fetcher?: typeof fetch
): Promise<CredentialDisplayDefinition> {
  const fetchFn = fetcher ?? globalThis.fetch;
  if (typeof fetchFn !== 'function') {
    throw new TypeError(
      'No fetch implementation available to resolve credential display definition'
    );
  }

  const response = await fetchFn(displayRef.uri);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch credential display definition from '${displayRef.uri}' (status ${response.status})`
    );
  }

  const payload: unknown = await response.json();
  if (!isCredentialDisplayDefinition(payload)) {
    validateCredentialDisplaySchema(payload);
    console.error(
      `[resolve] Invalid credential display definition from '${displayRef.uri}':`,
      (validateCredentialDisplaySchema as unknown as ValidateFunction).errors
    );
    throw new Error(`Invalid credential display definition payload from '${displayRef.uri}'`);
  }

  return payload;
}

/**
 * Resolves issuer metadata and credential display definition from entity statement metadata and SD-JWT payload.
 *
 * Matching logic:
 * - issuer metadata detection: JSON schema validation across entity statement metadata entries
 * - issuer match: sdjwt.iss === credential_configuration.credential_issuer
 * - type match:
 *   - VCSDJWT: uses vct
 *   - SDJWT: uses type claim
 *
 * @throws Error when entity statement metadata is missing/invalid, when issuer entity type cannot be uniquely
 * detected, or when no credential configuration matches issuer/type.
 */
export async function resolveAlbertaWallet<TES = unknown, TSDJWT extends SDJWT = SDJWT>(
  input: ResolveAlbertaWalletRequest<TSDJWT> & { es: TES }
): Promise<ResolveAlbertaWalletResult<TES, TSDJWT>> {
  const { es, sdjwt, fetcher } = input;

  const issuerConfig = extractAlbertaCredentialIssuer(es);
  const credentialType = resolveCredentialType(sdjwt);
  const credentialConfig = selectMatchingConfiguration(issuerConfig, sdjwt.iss, credentialType);
  const credentialDefinition = await fetchCredentialDefinition(
    credentialConfig.credential_definition,
    fetcher
  );
  const credentialDisplayDefinition = await fetchCredentialDisplayDefinition(
    credentialConfig.credential_display,
    fetcher
  );

  return {
    es,
    sdjwt,
    albertaCredentialIssuer: issuerConfig,
    credentialConfiguration: credentialConfig,
    credentialDefinition,
    credentialDisplayDefinition,
  };
}
