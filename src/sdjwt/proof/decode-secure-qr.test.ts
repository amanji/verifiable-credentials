import { CompactSign, generateKeyPair, SignJWT } from 'jose';
import pako from 'pako';
import { byteArrayToBase64, createToken } from '../../shared';
import { decodeSecureQr } from '../proof';
import {
  ProofTypeEnum,
  PresentationVerificationStatus,
  SecureQRProofValidationOptions,
} from '../types';
import { computeHash } from '../utilities';

const encoder = new TextEncoder();

describe('verifySecureQrPresentation - basic failure cases', () => {
  // These tests avoid building a valid SD-JWT credential or a real Secure-QR
  // proof. They only exercise the credential-failure path, so the signing key
  // resolver is never meaningfully invoked.

  const noopKeyResolver = () => Promise.resolve(new Uint8Array());
  const noopProofKeyResolver = () => Promise.resolve({} as CryptoKey);

  const options = {
    proofType: ProofTypeEnum.SECURE_QR,
    credentialSigningKeyResolver: noopKeyResolver,
    proofSigningKeyResolver: noopProofKeyResolver,
  };

  it('returns invalid-proof when the credential cannot be decoded', async () => {
    const result = await decodeSecureQr('not-a-valid-proof', 'token', options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toContain('Secure QR proof validation failed');
  });

  it('returns invalid-proof for a garbage credential with a proof token', async () => {
    const result = await decodeSecureQr('bad-proof', 'token', options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
  });

  it('returns invalid-proof for an empty string', async () => {
    const result = await decodeSecureQr('', '', options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toBeDefined();
  });
});

describe('verifySecureQrPresentation', () => {
  let vcPrivateKey: CryptoKey;
  let proofPrivateKey: CryptoKey;
  let proofPublicKey: CryptoKey;
  let vcToken: string;
  let vcHash: string;
  let now: number;
  let options: SecureQRProofValidationOptions;
  const proofSigningKeyResolver = () => Promise.resolve(proofPublicKey);

  beforeAll(async () => {
    const vcKeys = await generateKeyPair('RS256');
    vcPrivateKey = vcKeys.privateKey;

    const proofKeys = await generateKeyPair('ES256');
    proofPrivateKey = proofKeys.privateKey;
    proofPublicKey = proofKeys.publicKey;

    vcToken = await createToken(vcPrivateKey, false);
    vcHash = byteArrayToBase64(await computeHash(vcToken, 'sha-256'));
    now = Math.trunc(Date.now() / 1000);
    options = {
      proofType: ProofTypeEnum.SECURE_QR,
      proofSigningKeyResolver,
    };
  });

  async function createProof(
    proofPayload: Record<string, unknown>,
    compressed = false
  ): Promise<string> {
    const header = {
      alg: 'ES256',
      typ: 'JWT',
      ...(compressed ? { zip: 'DEF' } : {}),
    };

    const proofToken = compressed
      ? await new CompactSign(pako.deflateRaw(encoder.encode(JSON.stringify(proofPayload))))
          .setProtectedHeader(header)
          .sign(proofPrivateKey)
      : await new SignJWT(proofPayload).setProtectedHeader(header).sign(proofPrivateKey);

    return `${proofToken}`;
  }

  it('returns valid for a proof with matching vc_hash', async () => {
    const proof = await createProof({
      iss: 'did:example:wallet',
      iat: now,
      vc_hash: vcHash,
      type: 'ABAP',
    });

    const result = await decodeSecureQr(proof, vcToken, options);

    expect(result.valid).toBe(true);
    expect(result.warning).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.VALID);
    expect(result.proofIssuedAt).toBe(now);
  });

  it.each([
    ['missing', {}],
    ['incorrect', { vc_hash: 'not-the-right-hash' }],
  ])('returns invalid-proof for %s vc_hash', async (_label, proofExtras) => {
    const proof = await createProof({
      iss: 'did:example:wallet',
      iat: now,
      type: 'ABAP',
      ...proofExtras,
    });

    const result = await decodeSecureQr(proof, vcToken, options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toMatch(/vc_hash/);
  });

  it.each([
    ['missing', {}],
    ['non-numeric', { iat: 'not-a-number' }],
  ])('returns invalid-proof for %s iat', async (_label, proofExtras) => {
    const proof = await createProof({
      iss: 'did:example:wallet',
      vc_hash: vcHash,
      type: 'ABAP',
      ...proofExtras,
    });

    const result = await decodeSecureQr(proof, vcToken, options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toMatch(/iat/);
  });

  it('returns warning_proof_old when the proof is too old', async () => {
    const issuedAt = now - 3600;
    const proof = await createProof({
      iss: 'did:example:wallet',
      iat: issuedAt,
      vc_hash: vcHash,
      type: 'ABAP',
    });

    const result = await decodeSecureQr(proof, vcToken, options);

    expect(result.valid).toBe(true);
    expect(result.warning).toBe(true);
    expect(result.status).toBe(PresentationVerificationStatus.WARNING_PROOF_OLD);
    expect(result.proofIssuedAt).toBe(issuedAt);
  });

  it('verifies a compressed zip=DEF proof token', async () => {
    const proof = await createProof(
      {
        iss: 'did:example:wallet',
        iat: now,
        vc_hash: vcHash,
        type: 'ABAP',
      },
      true
    );

    const result = await decodeSecureQr(proof, vcToken, options);

    expect(result.valid).toBe(true);
    expect(result.warning).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.VALID);
  });
});
