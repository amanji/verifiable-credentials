import validateSDJWTSchema from './compiled/validate-sd-jwt.js';
import validateVCSDJWTSchema from './compiled/validate-vc-sd-jwt.js';

/**
 * Validates an SD-JWT payload against the SD-JWT JSON schema (RFC-9901)
 *
 * Performs JSON schema validation using AJV with draft 2020-12 support.
 * Validates that the payload contains required fields (iss, iat) and
 * that optional selective disclosure fields (_sd, _sd_alg) follow the schema rules.
 *
 * @param payload - The JWT payload object to validate
 * @returns Always returns true if validation succeeds
 * @throws {Error} If payload fails schema validation with detailed error messages
 *
 * @remarks
 * - Required fields: iss (string URI), iat (integer seconds)
 * - _sd_alg is optional and defaults to "sha-256" if _sd is present
 * - Additional properties are allowed for custom claims
 * - Error messages include field paths for precise identification
 */
export function validateSDJWTAgainstSchema(payload: unknown): true {
  const valid = validateSDJWTSchema(payload);
  if (!valid) {
    const errors =
      validateSDJWTSchema.errors?.map((err) => `${err.instancePath} ${err.message}`).join(', ') ||
      'Unknown validation error';
    throw new Error(`SD-JWT schema validation failed: ${errors}`);
  }
  return true;
}

/**
 * Validates a VC+SD-JWT payload against the VC+SD-JWT schema
 *
 * Extends SD-JWT schema validation with VC+SD-JWT specific requirements.
 * Validates that the payload contains required SD-JWT fields plus the vct field,
 * and optionally validates key binding confirmation (cnf) if present.
 *
 * @param payload - The JWT payload object to validate
 * @returns Always returns true if validation succeeds
 * @throws {Error} If payload fails schema validation with detailed error messages
 *
 * @remarks
 * - Inherits all SD-JWT validation rules (iss, iat required, _sd/_sd_alg rules, etc.)
 * - Requires vct field (VC Type) - must be URI format
 * - Optional cnf field for key binding: structurally validated according to the JSON schema
 * - Detailed cnf semantics (e.g., whether both jwk and jkt are present, or cnf is empty)
 *   are validated during decoding (see decode.ts), not by this schema validator
 * - Error messages include field paths for precise identification
 *
 * @see {@link validateSDJWTAgainstSchema} for base SD-JWT validation rules
 */
export function validateVCSDJWTAgainstSchema(payload: unknown): true {
  const valid = validateVCSDJWTSchema(payload);
  if (!valid) {
    const errors =
      validateVCSDJWTSchema.errors?.map((err) => `${err.instancePath} ${err.message}`).join(', ') ||
      'Unknown validation error';
    throw new Error(`VC+SD-JWT schema validation failed: ${errors}`);
  }
  return true;
}
