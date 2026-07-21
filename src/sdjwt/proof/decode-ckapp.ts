import * as jose from 'jose';
import { getCurrentUnixTime } from '../utilities';
import { CredentialProofResult } from './types';
import { CKAPPProofValidationOptions, PresentationVerificationStatus } from '../types';
import { PROOF_MAX_AGE_SECONDS } from '../decode';
import { base64ToBytes, concatBytes, uint8ArrayToBase64url } from '../../shared';
import { p256, bytesToHex, numberToBytesBE } from '../../shared/noble';

interface ParsedCKAPP {
  keyId: string;
  holderCompressedPublicKey: Uint8Array;
  attestationIat: number;
  proofIat: number;
  attestationProof: Uint8Array;
  holderProof: Uint8Array;
  sigU: Uint8Array;
  sigC: Uint8Array;
}

interface VerifyCKAPPResults {
  valid: boolean;
  error: string;
}

//See README for docs
export async function decodeCKAPP(
  proof: string,
  vcToken: string,
  options: CKAPPProofValidationOptions
): Promise<CredentialProofResult> {
  try {
    const parsed = parseCKAPP(proof, vcToken, options.expectedNonce);
    const { proofIat } = parsed;
    const verificationResults = await verifyCkappSignatures(parsed, options);

    if (!verificationResults.valid) {
      return {
        valid: false,
        status: PresentationVerificationStatus.INVALID_PROOF,
        error: `Proof verification failed: ${verificationResults.error}`,
      };
    }
    const proofAge = getCurrentUnixTime() - proofIat;
    if (proofAge > PROOF_MAX_AGE_SECONDS) {
      return {
        valid: false,
        status: PresentationVerificationStatus.INVALID_PROOF_OLD,
        error: 'CKAPP proof timestamp is older than allowed window',
        proofIssuedAt: proofIat,
      };
    }

    return {
      valid: true,
      status: PresentationVerificationStatus.VALID,
      proofIssuedAt: proofIat,
    };
  } catch (error) {
    return {
      valid: false,
      status: PresentationVerificationStatus.INVALID_PROOF,
      error: `Proof verification failed: ${error as Error}`,
    };
  }
}

//See README for docs
async function verifyCkappSignatures(
  parsed: ParsedCKAPP,
  options: CKAPPProofValidationOptions
): Promise<VerifyCKAPPResults> {
  const { keyId, holderCompressedPublicKey, attestationProof, holderProof, sigU, sigC } = parsed;

  if (!options.proofSigningKeyResolver) {
    return {
      valid: false,
      error: 'No proof signing key resolver provided for CKAPP verification',
    };
  }

  let resolvedProofPublicKey: CryptoKey | Uint8Array;
  try {
    resolvedProofPublicKey = await options.proofSigningKeyResolver('', keyId);
    if (resolvedProofPublicKey instanceof Uint8Array) {
      return {
        valid: false,
        error: 'Unsupported key material type for CKAPP verification',
      };
    }
  } catch {
    return {
      valid: false,
      error: `failed to resolve the key for attestation keyId '${keyId}'`,
    };
  }

  const importedProofPublicKey = await importEcPublicKey(resolvedProofPublicKey);

  const attestationSignatureValid = await verifyEs256RawSignature(
    importedProofPublicKey,
    attestationProof,
    sigC
  );

  if (!attestationSignatureValid) {
    return {
      valid: false,
      error: 'CKAPP attestation signature is invalid',
    };
  }

  const presenterPublicKey = await importCompressedP256PublicKey(holderCompressedPublicKey);

  const presenterSignatureValid = await verifyEs256RawSignature(
    presenterPublicKey,
    holderProof,
    sigU
  );
  if (!presenterSignatureValid) {
    return {
      valid: false,
      error: 'CKAPP holder signature is invalid',
    };
  }

  return {
    valid: true,
    error: '',
  };
}

function parseCKAPP(
  ckappBase64: string,
  vcToken: string,
  expectedNonce: Uint8Array | undefined
): ParsedCKAPP {
  const CKAPP_TOTAL_LENGTH = 182;
  const CKAPP_ATTESTATION_LENGTH = 106;
  const CKAPP_PROOF_LENGTH = 76;
  const CKAPP_HOLDER_COMPRESSED_KEY_LENGTH = 33;
  const CKAPP_ATTESTATION_CENTRAL_KID_LENGTH = 4;
  const CKAPP_ATTESTATION_IAT_LENGTH = 4;
  const CKAPP_PROOF_IAT_LENGTH = 4;
  const CKAPP_SIGNATURE_LENGTH = 64;

  const encoder = new TextEncoder();

  const CKAPP_VERSION = 1;
  const ATTEST_PREFIX = encoder.encode('ATSTv1');
  const PRESENT_PREFIX = encoder.encode('PRESv1');
  const TILDE_BYTE = encoder.encode('~');

  const bytes = base64ToBytes(ckappBase64);
  if (bytes.length !== CKAPP_TOTAL_LENGTH) {
    throw new Error(
      `CKAPP binary length must be ${CKAPP_TOTAL_LENGTH} bytes, received ${bytes.length}`
    );
  }

  const attestation = bytes.slice(0, CKAPP_ATTESTATION_LENGTH);
  const proof = bytes.slice(
    CKAPP_ATTESTATION_LENGTH,
    CKAPP_ATTESTATION_LENGTH + CKAPP_PROOF_LENGTH
  );

  const version = attestation[0];
  const keyId = attestation.slice(1, 1 + CKAPP_ATTESTATION_CENTRAL_KID_LENGTH);
  const holderCompressedPublicKey = attestation.slice(5, 5 + CKAPP_HOLDER_COMPRESSED_KEY_LENGTH);
  const attestationIat = attestation.slice(38, 38 + CKAPP_ATTESTATION_IAT_LENGTH);
  const sigC = attestation.slice(42, 42 + CKAPP_SIGNATURE_LENGTH);

  const proofIat = proof.slice(0, CKAPP_PROOF_IAT_LENGTH);
  const nonce = proof.slice(CKAPP_PROOF_IAT_LENGTH, CKAPP_PROOF_IAT_LENGTH + 8);
  const sigU = proof.slice(12, 12 + CKAPP_SIGNATURE_LENGTH);

  if (version !== CKAPP_VERSION) {
    throw new Error(`Unsupported CKAPP version '${version}'`);
  }

  if (holderCompressedPublicKey.length !== CKAPP_HOLDER_COMPRESSED_KEY_LENGTH) {
    throw new Error('Invalid holder public key length in CKAPP attestation');
  }

  if (sigC.length !== CKAPP_SIGNATURE_LENGTH || sigU.length !== CKAPP_SIGNATURE_LENGTH) {
    throw new Error('CKAPP signatures must be 64-byte raw r||s values');
  }

  if (expectedNonce) {
    if (
      expectedNonce.length !== nonce.length ||
      !expectedNonce.every((value, i) => value === nonce[i])
    ) {
      throw new Error('CKAPP nonce does not match expected challenge');
    }
  }

  const attestationProof = concatBytes(
    ATTEST_PREFIX,
    new Uint8Array([version]),
    keyId,
    holderCompressedPublicKey,
    attestationIat
  );

  const holderProof = concatBytes(
    PRESENT_PREFIX,
    encoder.encode(vcToken),
    TILDE_BYTE,
    attestation,
    proofIat,
    nonce
  );

  return {
    keyId: readUint32BE(keyId, 0).toString(),
    holderCompressedPublicKey,
    attestationIat: readUint32BE(attestationIat, 0),
    proofIat: readUint32BE(proofIat, 0),
    attestationProof,
    holderProof,
    sigU,
    sigC,
  };
}

function readUint32BE(bytes: Uint8Array, offset: number): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, false);
}

async function verifyEs256RawSignature(
  key: CryptoKey,
  message: Uint8Array,
  signatureRaw: Uint8Array
): Promise<boolean> {
  if (signatureRaw.length !== 64) {
    throw new Error(`Expected 64-byte raw signature, received ${signatureRaw.length}`);
  }
  const rawVerified = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new Uint8Array(signatureRaw),
    new Uint8Array(message)
  );
  if (rawVerified) {
    return true;
  }

  const signatureDer = rawEcdsaSignatureToDer(signatureRaw);
  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new Uint8Array(signatureDer),
    new Uint8Array(message)
  );
}

async function importEcPublicKey(keyMaterial: CryptoKey | JsonWebKey): Promise<CryptoKey> {
  if (isCryptoKey(keyMaterial)) {
    return keyMaterial;
  }

  const imported = await jose.importJWK(keyMaterial, 'ES256');
  if (!isCryptoKey(imported)) {
    throw new Error('Expected EC JWK import to resolve to a CryptoKey');
  }

  return imported;
}

async function importCompressedP256PublicKey(compressedKey: Uint8Array): Promise<CryptoKey> {
  if (compressedKey.length !== 33) {
    throw new Error('Compressed P-256 public key must be 33 bytes');
  }

  const prefix = compressedKey[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error('Compressed P-256 public key must start with 0x02 or 0x03');
  }

  let affine: { x: bigint; y: bigint };
  try {
    affine = p256.Point.fromHex(bytesToHex(compressedKey)).toAffine();
  } catch {
    throw new Error('Compressed P-256 public key is not a valid curve point');
  }

  const imported = await jose.importJWK(
    {
      kty: 'EC',
      crv: 'P-256',
      x: uint8ArrayToBase64url(numberToBytesBE(affine.x, 32)),
      y: uint8ArrayToBase64url(numberToBytesBE(affine.y, 32)),
    },
    'ES256'
  );

  if (!isCryptoKey(imported)) {
    throw new Error('Expected compressed EC key import to resolve to a CryptoKey');
  }

  return imported;
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return (
    typeof value === 'object' &&
    value !== null &&
    'type' in value &&
    'algorithm' in value &&
    'usages' in value &&
    'extractable' in value
  );
}

function rawEcdsaSignatureToDer(signatureRaw: Uint8Array): Uint8Array {
  if (signatureRaw.length !== 64) {
    throw new Error(`Expected 64-byte raw signature, received ${signatureRaw.length}`);
  }

  const r = derEncodeInteger(signatureRaw.slice(0, 32));
  const s = derEncodeInteger(signatureRaw.slice(32, 64));
  const totalLength = r.length + s.length;

  const der = new Uint8Array(2 + totalLength);
  der[0] = 0x30;
  der[1] = totalLength;
  der.set(r, 2);
  der.set(s, 2 + r.length);
  return der;
}

function derEncodeInteger(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start += 1;
  }

  let normalized = value.slice(start);
  if ((normalized[0] ?? 0) >= 0x80) {
    const prefixed = new Uint8Array(normalized.length + 1);
    prefixed[0] = 0;
    prefixed.set(normalized, 1);
    normalized = prefixed;
  }

  const result = new Uint8Array(2 + normalized.length);
  result[0] = 0x02;
  result[1] = normalized.length;
  result.set(normalized, 2);
  return result;
}
