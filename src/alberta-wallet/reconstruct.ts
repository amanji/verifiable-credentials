/**
 * SD-JWT Reconstruction
 * Reconstructs SD-JWT tokens with selected disclosures
 */

import type { DecodeInput } from '../sdjwt';
import { decodeSDJWT } from '../sdjwt';

/**
 * Result of reconstructing an SD-JWT token
 */
export interface ReconstructResult {
  /** Whether the operation was successful */
  valid: boolean;
  /** The reconstructed SD-JWT token with only selected disclosures */
  token?: string;
  /** Error message if the operation failed */
  error?: string;
}

// Backward-compatible alias for existing consumers that imported the older result name.
export type ReconstructSDJWTResult = ReconstructResult;

/**
 * Reconstructs an SD-JWT token with only the specified disclosures included.
 *
 * This function takes an SD-JWT token (either as a combined format string or
 * structured input) and a list of claim names to include. It returns a new
 * SD-JWT token containing only the specified disclosures.
 *
 * @param input - The SD-JWT token to process. Can be:
 *                - A combined SD-JWT string: "JWT~disclosure1~disclosure2~..."
 *                - An object with `vcToken` and optional `selectiveDisclosures`
 * @param claimNames - Array of claim names to include in the output token.
 *                     Only disclosures matching these names will be included.
 *                     If empty, returns the JWT without any disclosures, but
 *                     still includes the attestation segment if one is provided.
 * @param attestation - Optional attestation string to include in the reconstructed token.
 * @returns A result object containing:
 *          - `valid`: true if the operation succeeded
 *          - `token`: the reconstructed SD-JWT with selected disclosures and
 *            optional attestation
 *          - `error`: error message if the operation failed
 *
 * @example
 * Reconstruct with only 'age' and 'country' disclosures:
 * ```typescript
 * const sdJwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.sig~disc1~disc2~disc3~";
 * const result = reconstructSDJWT(sdJwt, ['age', 'country']);
 * if (result.valid) {
 *   console.log(result.token); // JWT with only age and country disclosures
 * }
 * ```
 *
 * @example
 * Using structured input:
 * ```typescript
 * const result = reconstructSDJWT({
 *   vcToken: jwtToken,
 *   selectiveDisclosures: allDisclosures
 * }, ['firstName', 'lastName']);
 * ```
 */
export async function reconstructSDJWT(
  input: DecodeInput,
  claimNames: string[] = [],
  attestation?: string
): Promise<ReconstructResult> {
  try {
    const { rawData, rawDisclosures } = await decodeSDJWT(input, { verifySignature: false });

    if (claimNames.length === 0) {
      const token = [rawData, attestation].filter(Boolean).join('~');
      return {
        valid: true,
        token,
      };
    }

    // Convert claimNames to a Set for efficient lookup
    const claimNamesSet = new Set(claimNames);

    // Filter disclosures by claim name
    const selectedDisclosureStrings: string[] = [];
    if (rawDisclosures && Object.keys(rawDisclosures).length > 0) {
      for (const [claimName, claimValue] of Object.entries(rawDisclosures)) {
        if (claimNamesSet.has(claimName)) {
          selectedDisclosureStrings.push(claimValue as string);
        }
      }
    }

    const tokenParts = [rawData, ...selectedDisclosureStrings, attestation];
    const token = tokenParts.filter(Boolean).join('~');

    return {
      valid: true,
      token,
    };
  } catch (err) {
    return {
      valid: false,
      error: `Failed to reconstruct SD-JWT: ${err instanceof Error ? err.message : 'Unknown error'}`,
    };
  }
}
