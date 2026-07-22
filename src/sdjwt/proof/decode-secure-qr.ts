import * as jose from 'jose';
import { computeHash, decompressString, getCurrentUnixTime } from '../utilities';
import { CredentialProofResult } from './types';
import { PROOF_MAX_AGE_SECONDS } from '../decode';
import { PresentationVerificationStatus, SecureQRProofValidationOptions } from '../types';
import { byteArrayToBase64 } from '../../shared';

interface SecureQrProofPayload {
  iss?: unknown;
  iat?: unknown;
  vc_hash?: unknown;
}

//See Readme for docs
export async function decodeSecureQr(
  proofToken: string,
  vcToken: string,
  options: SecureQRProofValidationOptions
): Promise<CredentialProofResult> {
  let issuedAt: number | undefined;
  const { proofSigningKeyResolver } = options;

  try {
    const header = jose.decodeProtectedHeader(proofToken);
    const jwtParts = proofToken.split('.');
    if (jwtParts.length !== 3) {
      throw new Error('Invalid proof JWT format');
    }

    const headerAlg = typeof header.alg === 'string' ? header.alg : undefined;
    const headerKid = typeof header.kid === 'string' ? header.kid : undefined;
    const isCompressed = typeof header.zip === 'string' && header.zip.toUpperCase() === 'DEF';

    let payload: SecureQrProofPayload;
    if (isCompressed) {
      try {
        payload = JSON.parse(decompressString(jwtParts[1])) as SecureQrProofPayload;
      } catch (decompressError) {
        throw new Error(
          `Secure QR compressed payload decode failed: ${decompressError instanceof Error ? decompressError.message : 'Unknown error'}`
        );
      }
    } else {
      payload = jose.decodeJwt(proofToken);
    }

    const proofIssuer = typeof payload.iss === 'string' ? payload.iss : undefined;
    if (!proofIssuer) {
      throw new Error('Secure QR proof is missing iss claim');
    }

    const keyMaterial = await proofSigningKeyResolver(proofIssuer, headerKid, headerAlg);

    if (isCompressed) {
      await jose.compactVerify(proofToken, keyMaterial);
    } else {
      await jose.jwtVerify(proofToken, keyMaterial);
    }

    const vcHash = typeof payload.vc_hash === 'string' ? payload.vc_hash : undefined;
    if (!vcHash) {
      return {
        valid: false,
        status: PresentationVerificationStatus.INVALID_PROOF,
        error: 'Secure QR proof missing vc_hash claim',
      };
    }
    const expectedVcHash = byteArrayToBase64(await computeHash(vcToken, 'sha-256'));
    if (expectedVcHash !== vcHash) {
      return {
        valid: false,
        status: PresentationVerificationStatus.INVALID_PROOF,
        error: 'Secure QR proof vc_hash does not match credential',
      };
    }

    issuedAt = typeof payload.iat === 'number' ? payload.iat : undefined;
    if (issuedAt === undefined) {
      return {
        valid: false,
        status: PresentationVerificationStatus.INVALID_PROOF,
        error: 'Secure QR proof missing iat claim',
      };
    }

    const proofAge = getCurrentUnixTime() - issuedAt;
    if (proofAge > PROOF_MAX_AGE_SECONDS) {
      return {
        valid: true,
        warning: true,
        status: PresentationVerificationStatus.WARNING_PROOF_OLD,
        proofIssuedAt: issuedAt,
      };
    }
  } catch (error) {
    return {
      valid: false,
      status: PresentationVerificationStatus.INVALID_PROOF,
      error: `Secure QR proof validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }

  return {
    valid: true,
    warning: false,
    status: PresentationVerificationStatus.VALID,
    proofIssuedAt: issuedAt,
  };
}
