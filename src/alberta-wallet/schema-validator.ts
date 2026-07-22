import validateAlbertaCredentialIssuerSchema from './compiled/validate-alberta-credential-issuer.js';
import validateCredentialDisplaySchema from './compiled/validate-credential-display.js';
import type { AlbertaCredentialIssuer, CredentialDisplayDefinition } from './types';

/**
 * Runtime type guard based on `alberta-credential-issuer-v1.json`.
 */
export function isAlbertaCredentialIssuer(value: unknown): value is AlbertaCredentialIssuer {
  return Boolean(validateAlbertaCredentialIssuerSchema(value));
}

/**
 * Runtime type guard based on `card-display-v1.json`.
 */
export function isCredentialDisplayDefinition(
  value: unknown
): value is CredentialDisplayDefinition {
  return Boolean(validateCredentialDisplaySchema(value));
}
