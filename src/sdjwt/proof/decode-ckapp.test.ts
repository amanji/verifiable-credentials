import {
  createCkappProof,
  getCurrentUnixTimeForTest,
  createToken,
  createKeysForTests,
  base64ToBytes,
  byteArrayToBase64,
} from '../../shared';
import { PresentationVerificationStatus, ProofTypeEnum } from '../types';
import { decodeCKAPP } from './decode-ckapp';

describe('decodeCKAPP - test cases', () => {
  // The credential signing key resolver is required by the options type but is
  // never invoked for these cases, since decoding short-circuits before any
  // signature verification. A no-op resolver keeps the test free of key mocks.

  let vcPrivateKey: CryptoKey;
  let proofPrivateKey: CryptoKey;
  let proofPublicKey: CryptoKey;

  beforeAll(async () => {
    const keys = await createKeysForTests();
    vcPrivateKey = keys.vcPrivateKey;
    proofPrivateKey = keys.proofPrivateKey;
    proofPublicKey = keys.proofPublicKey;
  });

  const options = {
    proofType: ProofTypeEnum.CKAPP,
    proofSigningKeyResolver: () => Promise.resolve(proofPublicKey),
  };

  it('returns valid for a fully valid CKAPP (attestation + holder proof)', async () => {
    const { proof, token } = await createValidCkappProof(
      vcPrivateKey,
      proofPrivateKey,
      proofPublicKey
    );
    const result = await decodeCKAPP(proof, token, options);

    expect(result.valid).toBe(true);
    expect(result.status).toBe(PresentationVerificationStatus.VALID);
  });

  it('returns invalid-proof for unsupported CKAPP version in attestation', async () => {
    const { proof, token } = await createValidCkappProof(
      vcPrivateKey,
      proofPrivateKey,
      proofPublicKey
    );
    const mutatedProof = mutateCkappBytes(proof, (bytes) => {
      bytes[0] = 2; // attestation version byte
    });

    const result = await decodeCKAPP(mutatedProof, token, options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toContain('Unsupported CKAPP version');
  });

  it('returns invalid-proof when key cannot be resolved by keyId', async () => {
    const { proof, token } = await createValidCkappProof(
      vcPrivateKey,
      proofPrivateKey,
      proofPublicKey
    );
    const result = await decodeCKAPP(proof, token, {
      ...options,
      proofSigningKeyResolver: () => Promise.reject(new Error('no key')),
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toContain('failed to resolve the key for attestation keyId');
  });

  it('returns invalid-proof when attestation signature sigC is invalid', async () => {
    const { proof, token } = await createValidCkappProof(
      vcPrivateKey,
      proofPrivateKey,
      proofPublicKey
    );
    const mutatedProof = mutateCkappBytes(proof, (bytes) => {
      bytes[42] ^= 0x01; // first byte of sigC (attestation signature starts at 42)
    });

    const result = await decodeCKAPP(mutatedProof, token, options);

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toContain('CKAPP attestation signature is invalid');
  });

  it('returns invalid-proof when proof resolver returns unsupported key material for keyId', async () => {
    const { proof, token } = await createValidCkappProof(
      vcPrivateKey,
      proofPrivateKey,
      proofPublicKey
    );
    const result = await decodeCKAPP(proof, token, {
      ...options,
      proofSigningKeyResolver: () => Promise.resolve(new Uint8Array([1, 2, 3])),
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe(PresentationVerificationStatus.INVALID_PROOF);
    expect(result.error).toContain('Unsupported key material type');
  });
});

async function createValidCkappProof(
  vcPrivateKey: CryptoKey,
  proofPrivateKey: CryptoKey,
  proofPublicKey: CryptoKey
): Promise<{ proof: string; token: string }> {
  const vcToken = await createToken(vcPrivateKey, false);

  return {
    proof: await createCkappProof({
      vcToken,
      keyId: 1,
      attestationPrivateKey: proofPrivateKey,
      holderPrivateKey: proofPrivateKey,
      holderPublicKey: proofPublicKey,
      attestationIat: getCurrentUnixTimeForTest(),
      proofIat: getCurrentUnixTimeForTest(),
      nonce: new Uint8Array(8).fill(0x01), // Dummy nonce
    }),
    token: vcToken,
  };
}

function mutateCkappBytes(proof: string, mutate: (bytes: Uint8Array) => void): string {
  const bytes = base64ToBytes(proof);
  mutate(bytes);
  return byteArrayToBase64(bytes);
}
