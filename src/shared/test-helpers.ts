/**
 * Shared Test Helpers
 * Common test utility functions for creating and signing JWT tokens
 * Used across vclib test suites
 */

import * as jose from 'jose';
import pako from 'pako';
import { concatBytes, numberToBytesBE } from '../shared';
import { base64urlToBytes, byteArrayToBase64 } from './utilities';

// Constants for Unix epoch time conversion
const MILLISECONDS_PER_SECOND = 1000;

const encoder = new TextEncoder();

interface CkappPresentationRequest {
  vcToken: string;
  keyId: number;
  attestationPrivateKey: CryptoKey;
  holderPrivateKey: CryptoKey;
  holderPublicKey: CryptoKey;
  attestationIat: number;
  proofIat: number;
  nonce: Uint8Array;
}

/**
 * Get current Unix epoch time in seconds (for testing)
 *
 * @returns Current time as Unix epoch timestamp in seconds
 */
export function getCurrentUnixTimeForTest(): number {
  return Math.trunc(Date.now() / MILLISECONDS_PER_SECOND);
}

async function deflateRawAsync(data: Uint8Array): Promise<Uint8Array> {
  const compressed = pako.deflateRaw(data);
  return Promise.resolve(
    compressed instanceof Uint8Array ? compressed : new Uint8Array(compressed)
  );
}

async function createSignedJWT(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  typ?: string
): Promise<string> {
  const header: { alg: string; typ?: string } = { alg: 'RS256' };
  if (typ) {
    header.typ = typ;
  }
  return new jose.SignJWT(payload).setProtectedHeader(header).sign(privateKey);
}

async function createSignedCompressedJWT(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  typ?: string
): Promise<string> {
  const header: { alg: string; zip: string; typ?: string } = { alg: 'RS256', zip: 'DEF' };
  if (typ) {
    header.typ = typ;
  }
  const payloadBytes = encoder.encode(JSON.stringify(payload));
  const compressed = await deflateRawAsync(new Uint8Array(payloadBytes));
  return await new jose.CompactSign(compressed).setProtectedHeader(header).sign(privateKey);
}

export function createTokenPayload(
  payloadOverrides?: Partial<Record<string, unknown>>
): Record<string, unknown> {
  const now = getCurrentUnixTimeForTest();

  return {
    iss: 'did:example:issuer',
    sub: 'did:example:subject',
    iat: now,
    exp: now + 3600,
    ...payloadOverrides,
  };
}

/**
 * Factory for creating and signing a token with default or custom values
 */
export async function createToken(
  privateKey: CryptoKey,
  compressed: boolean,
  payloadOverrides?: Partial<Record<string, unknown>>,
  typ?: string
): Promise<string> {
  const payload = createTokenPayload(payloadOverrides);
  // Default to 'sd-jwt' if typ is not provided
  const tokenType = typ || 'sd-jwt';
  return compressed
    ? createSignedCompressedJWT(payload, privateKey, tokenType)
    : createSignedJWT(payload, privateKey, tokenType);
}

export async function createKeysForTests() {
  const vcKeys = await jose.generateKeyPair('RS256');
  const proofKeys = await jose.generateKeyPair('ES256');

  return {
    vcPrivateKey: vcKeys.privateKey,
    vcPublicKey: vcKeys.publicKey,
    proofPrivateKey: proofKeys.privateKey,
    proofPublicKey: proofKeys.publicKey,
  };
}

/**
 * Factory for creating and signing a CKAPP attestation for validation.
 */
export async function createCkappProof(input: CkappPresentationRequest): Promise<string> {
  const holderPublicJwk = await jose.exportJWK(input.holderPublicKey);
  const holderCompressed = compressHolderPublicKey(holderPublicJwk);

  const attestationNoSig = concatBytes(
    new Uint8Array([0x01]),
    numberToBytesBE(input.keyId, 4),
    holderCompressed,
    numberToBytesBE(input.attestationIat, 4)
  );

  const mC = concatBytes(encoder.encode('ATSTv1'), attestationNoSig);

  const sigCDer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    input.attestationPrivateKey,
    new Uint8Array(mC)
  );
  const sigCRaw = derToRawSignature(new Uint8Array(sigCDer));
  const attestation = concatBytes(attestationNoSig, sigCRaw);

  const proofUnsigned = concatBytes(numberToBytesBE(input.proofIat, 4), input.nonce);

  const ckappNoSig = concatBytes(attestation, proofUnsigned);
  const mU = concatBytes(
    encoder.encode('PRESv1'),
    encoder.encode(input.vcToken),
    new Uint8Array([0x7e]),
    ckappNoSig
  );

  const sigUDer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    input.holderPrivateKey,
    new Uint8Array(mU)
  );
  const sigURaw = derToRawSignature(new Uint8Array(sigUDer));

  const ckapp = concatBytes(attestation, proofUnsigned, sigURaw);
  return byteArrayToBase64(ckapp);
}

function compressHolderPublicKey(publicJwk: JsonWebKey): Uint8Array {
  const x = base64urlToBytes(publicJwk.x as string);
  const y = base64urlToBytes(publicJwk.y as string);

  const compressed = new Uint8Array(33);
  compressed[0] = (y[31] & 1) === 0 ? 0x02 : 0x03;
  compressed.set(x, 1);
  return compressed;
}

function derToRawSignature(der: Uint8Array): Uint8Array {
  if (der.length === 64) {
    return der;
  }

  if (der[0] !== 0x30) {
    throw new Error('Invalid DER sequence');
  }

  let offset = 2;
  if (der[offset] !== 0x02) {
    throw new Error('Invalid DER integer for r');
  }
  const rLength = der[offset + 1];
  const r = der.slice(offset + 2, offset + 2 + rLength);

  offset += 2 + rLength;
  if (der[offset] !== 0x02) {
    throw new Error('Invalid DER integer for s');
  }
  const sLength = der[offset + 1];
  const s = der.slice(offset + 2, offset + 2 + sLength);

  const raw = new Uint8Array(64);
  raw.set(trimOrPad32(r), 0);
  raw.set(trimOrPad32(s), 32);
  return raw;
}

function trimOrPad32(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 32) {
    return bytes;
  } else if (bytes.length > 32) {
    return bytes.slice(bytes.length - 32);
  } else {
    const padded = new Uint8Array(32);
    padded.set(bytes, 32 - bytes.length);
    return padded;
  }
}
