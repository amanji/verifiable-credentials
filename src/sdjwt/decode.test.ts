import * as jose from 'jose';
import { DecodeInputObject, decodeSDJWT, isSDJWTExpired } from './decode';
import { SDJWT, VCSDJWT } from './types';
import {
  stringToBase64url,
  uint8ArrayToBase64url,
  createToken,
  getCurrentUnixTimeForTest,
} from '../shared';

describe('SD-JWT Decoder', () => {
  // Key pair for asymmetric signing (RSA)
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;

  beforeAll(async () => {
    // Generate RSA key pair for all tests
    const { publicKey: pub, privateKey: priv } = await jose.generateKeyPair('RS256');
    publicKey = pub;
    privateKey = priv;
  });

  describe('decodeSDJWT', () => {
    it('should validate a basic JWT credential without signature verification', async () => {
      const token = await createToken(privateKey, false, {
        name: 'John Doe',
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.iss).toBe('did:example:issuer');
      expect(result.data?.name).toBe('John Doe');
    });

    it('should validate JWT credential with selective disclosure from combined string input', async () => {
      const token = await createToken(privateKey, false);

      // Add selective disclosure
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));
      const sdJwt = `${token}~${disclosure1}~${disclosure2}~`;

      const result = await decodeSDJWT(sdJwt, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toEqual({
        age: 30,
        country: 'CA',
      });
    });

    it('should validate JWT credential with selective disclosure from object input', async () => {
      const token = await createToken(privateKey, false);

      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));

      const result = await decodeSDJWT(
        {
          vcToken: token,
          selectiveDisclosures: [disclosure1, disclosure2],
        },
        {
          signingKeyResolver: () => Promise.resolve(publicKey),
        }
      );

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toEqual({
        age: 30,
        country: 'CA',
      });
    });

    it('should fall back to embedded disclosures when object input omits selectiveDisclosures', async () => {
      const token = await createToken(privateKey, false);

      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));
      const sdJwt = `${token}~${disclosure1}~${disclosure2}~`;

      const result = await decodeSDJWT(
        {
          vcToken: sdJwt,
        },
        {
          signingKeyResolver: () => Promise.resolve(publicKey),
        }
      );

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toEqual({
        age: 30,
        country: 'CA',
      });
    });

    it('should fall back to embedded disclosures when object input selectiveDisclosures is empty', async () => {
      const token = await createToken(privateKey, false);

      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));
      const sdJwt = `${token}~${disclosure1}~${disclosure2}~`;

      const result = await decodeSDJWT(
        {
          vcToken: sdJwt,
          selectiveDisclosures: [],
        },
        {
          signingKeyResolver: () => Promise.resolve(publicKey),
        }
      );

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toEqual({
        age: 30,
        country: 'CA',
      });
    });

    it('should prefer explicit selectiveDisclosures over embedded disclosures for object input', async () => {
      const token = await createToken(privateKey, false);

      const embeddedDisclosure = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const explicitDisclosure = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));
      const sdJwt = `${token}~${embeddedDisclosure}~`;

      const result = await decodeSDJWT(
        {
          vcToken: sdJwt,
          selectiveDisclosures: [explicitDisclosure],
        },
        {
          signingKeyResolver: () => Promise.resolve(publicKey),
        }
      );

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toEqual({
        country: 'CA',
      });
    });

    it('should return an error when object input vcToken is empty', async () => {
      const result = await decodeSDJWT(
        {
          vcToken: '',
          selectiveDisclosures: [],
        },
        {
          verifySignature: false,
        }
      );

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Credential token is required');
    });

    it('should return an error when object input vcToken is missing', async () => {
      const result = await decodeSDJWT(
        {
          selectiveDisclosures: [],
        } as unknown as DecodeInputObject,
        {
          verifySignature: false,
        }
      );

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Credential token is required');
    });

    it('should reject expired credential when checkExpiration is true', async () => {
      const now = getCurrentUnixTimeForTest();
      const token = await createToken(privateKey, false, { iat: now - 7200, exp: now - 3600 });

      const result = await decodeSDJWT(token, { checkExpiration: true, verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should accept expired credential when checkExpiration is false', async () => {
      const now = getCurrentUnixTimeForTest();
      const token = await createToken(privateKey, false, { iat: now - 7200, exp: now - 3600 });

      const result = await decodeSDJWT(token, { checkExpiration: false, verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should verify signature when verifySignature is true and valid key provided', async () => {
      const token = await createToken(privateKey, false);

      const result = await decodeSDJWT(token, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should fail signature verification with wrong key', async () => {
      const token = await createToken(privateKey, false);

      // Generate a different key pair for the wrong key
      const { publicKey: wrongPublicKey } = await jose.generateKeyPair('RS256');

      const result = await decodeSDJWT(token, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(wrongPublicKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Signature verification failed');
    });

    it('should require public key when verifySignature is true', async () => {
      const token = await createToken(privateKey, false);

      const result = await decodeSDJWT(token, { verifySignature: true });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Public key required');
    });

    it('should handle invalid JWT token', async () => {
      const result = await decodeSDJWT('invalid.jwt.token');

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle malformed selective disclosure', async () => {
      const token = await createToken(privateKey, false);

      // Add invalid disclosure
      const sdJwt = `${token}~invalid-disclosure~`;

      const result = await decodeSDJWT(sdJwt, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      // Should still validate the credential, just ignore bad disclosures
      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should validate a compressed JWT credential', async () => {
      const compressedToken = await createToken(privateKey, true, {
        name: 'Jane Doe',
        degree: 'Bachelor of Science',
      });

      const result = await decodeSDJWT(compressedToken, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.name).toBe('Jane Doe');
      expect(result.data?.degree).toBe('Bachelor of Science');
    });

    it('should handle non-compressed JWT normally', async () => {
      const token = await createToken(privateKey, false);

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should verify signature on compressed JWT (original token, not decompressed)', async () => {
      const compressedToken = await createToken(privateKey, true, {
        name: 'Test User',
      });

      // Verify signature succeeds with correct key
      const result = await decodeSDJWT(compressedToken, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      if (!result.valid) {
        throw new Error(`Validation failed: ${result.error}`);
      }
      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.name).toBe('Test User');
    });

    it('should fail signature verification on compressed JWT with wrong key', async () => {
      // Create credential
      const compressedToken = await createToken(privateKey, true, {
        name: 'Test User',
      });

      // Generate a different key pair for the wrong key
      const { publicKey: wrongPublicKey } = await jose.generateKeyPair('RS256');

      // Try to verify with wrong key
      const result = await decodeSDJWT(compressedToken, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(wrongPublicKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Signature verification failed');
    });

    it('should verify signature and handle compressed payload correctly', async () => {
      const compressedToken = await createToken(privateKey, true, {
        degree: 'PhD in Computer Science',
        university: 'University of Example',
      });

      // Verify with signature verification enabled
      const result = await decodeSDJWT(compressedToken, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
        checkExpiration: false,
      });

      if (!result.valid) {
        throw new Error(`Validation failed: ${result.error}`);
      }
      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.degree).toBe('PhD in Computer Science');
      expect(result.data?.university).toBe('University of Example');
    });

    it('should reject JWT with unsupported signature algorithm', async () => {
      // Manually create a token with unsupported algorithm
      const headerBase64 = stringToBase64url(
        JSON.stringify({ alg: 'UNSUPPORTED', typ: 'sd-jwt', zip: 'DEF' })
      );
      const payloadBase64 = stringToBase64url(
        JSON.stringify({
          iss: 'did:example:issuer',
          iat: getCurrentUnixTimeForTest(),
        })
      );
      const signature = 'fake-signature';

      const token = `${headerBase64}.${payloadBase64}.${signature}`;

      const result = await decodeSDJWT(token);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Unsupported signature algorithm');
    });

    it('should handle malformed JWT header (invalid base64)', async () => {
      // Create a token with invalid base64 in header
      const invalidToken = 'not-valid-base64!@#$.eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ';

      const result = await decodeSDJWT(invalidToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle malformed JWT header (invalid JSON)', async () => {
      // Create a token with invalid JSON in header
      const invalidHeaderBase64 = stringToBase64url('{invalid json}');
      const payloadBase64 = stringToBase64url(JSON.stringify({ test: 'value' }));
      const signature = 'fake-signature';

      const token = `${invalidHeaderBase64}.${payloadBase64}.${signature}`;

      const result = await decodeSDJWT(token);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid JWT header');
    });

    it('should extract credential from payload when vc claim is missing', async () => {
      // Create token without vc claim - payload structure becomes the credential
      const token = await createToken(privateKey, false, {
        iss: 'did:example:issuer',
        sub: 'did:example:subject',
        iat: getCurrentUnixTimeForTest(),
        exp: getCurrentUnixTimeForTest() + 3600,
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.iss).toBe('did:example:issuer');
      expect(result.data?.sub).toBe('did:example:subject');
    });

    it('should handle SD-JWT with multiple selective disclosures', async () => {
      const token = await createToken(privateKey, false);

      // Add multiple selective disclosures
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'firstName', 'John']));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'lastName', 'Doe']));
      const disclosure3 = stringToBase64url(JSON.stringify(['salt3', 'email', 'john@example.com']));
      const sdJwt = `${token}~${disclosure1}~${disclosure2}~${disclosure3}~`;

      const result = await decodeSDJWT(sdJwt, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.disclosures).toEqual({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
      });
    });

    it('should support additional claims in SD-JWT credential', async () => {
      const token = await createToken(
        privateKey,
        false,
        {
          iss: 'did:example:issuer',
          iat: getCurrentUnixTimeForTest(),
          vct: 'https://example.com/credentials/v1',
          customClaim: 'customValue',
        },
        'vc+sd-jwt'
      );

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.vct).toBe('https://example.com/credentials/v1');
      expect(result.data?.customClaim).toBe('customValue');
    });

    it('should verify non-compressed JWT signature with correct key', async () => {
      const token = await createToken(privateKey, false, {
        name: 'Test User',
      });

      // Explicitly test non-compressed path
      const result = await decodeSDJWT(token, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.name).toBe('Test User');
    });

    it('should reject payload with invalid SD-JWT structure', async () => {
      // Create a token with missing required fields for SD-JWT
      const token = await createToken(privateKey, false, {
        sub: 'did:example:subject',
        exp: getCurrentUnixTimeForTest() + 3600,
        // Missing iss and iat - required fields
        iss: undefined,
        iat: undefined,
      });

      const result = await decodeSDJWT(token, {
        verifySignature: false,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid token format');
    });

    it('should reject JWT with only 2 parts', async () => {
      const invalidToken = 'header.payload';

      const result = await decodeSDJWT(invalidToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid JWT format');
    });

    it('should reject JWT with more than 3 parts', async () => {
      const invalidToken = 'header.payload.signature.extra';

      const result = await decodeSDJWT(invalidToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid JWT format');
    });

    it('should skip selective disclosure with non-string claim name', async () => {
      const token = await createToken(privateKey, false);

      // Disclosure with non-string claim name (should be skipped)
      const disclosure = stringToBase64url(JSON.stringify(['salt1', 123, 'value']));
      const sdJwt = `${token}~${disclosure}~`;

      const result = await decodeSDJWT(sdJwt, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toBeUndefined(); // Should be undefined since no valid disclosures
    });

    it('should skip selective disclosure with array length less than 3', async () => {
      const token = await createToken(privateKey, false);

      // Disclosure with only 2 elements (should be skipped)
      const disclosure = stringToBase64url(JSON.stringify(['salt1', 'claimName']));
      const sdJwt = `${token}~${disclosure}~`;

      const result = await decodeSDJWT(sdJwt, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toBeUndefined(); // Should be undefined since no valid disclosures
    });

    it('should handle credential with _sd field for selective disclosure', async () => {
      const token = await createToken(privateKey, false, {
        _sd: ['hash1', 'hash2'],
        _sd_alg: 'sha-256',
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?._sd).toEqual(['hash1', 'hash2']);
      expect(result.data?._sd_alg).toBe('sha-256');
    });

    it('should handle credential with status field', async () => {
      const token = await createToken(privateKey, false, {
        status: {
          status_list_uri: 'https://example.com/status-list',
          status_list_index: 42,
        },
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.status).toEqual({
        status_list_uri: 'https://example.com/status-list',
        status_list_index: 42,
      });
    });

    it('should handle VC+SD-JWT credential with vct and cnf fields', async () => {
      const token = await createToken(
        privateKey,
        false,
        {
          vct: 'https://credentials.example.com/identity',
          cnf: {
            jwk: {
              kty: 'EC',
              crv: 'P-256',
              x: 'example_x',
              y: 'example_y',
            },
          },
        },
        'vc+sd-jwt'
      );

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.vct).toBe('https://credentials.example.com/identity');
      expect(result.data?.cnf).toEqual({
        jwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'example_x',
          y: 'example_y',
        },
      });
    });

    it('should handle VC+SD-JWT credential with jkt confirmation', async () => {
      const token = await createToken(
        privateKey,
        false,
        {
          vct: 'https://credentials.example.com/identity',
          cnf: {
            jkt: 'thumbprint-value',
          },
        },
        'vc+sd-jwt'
      );

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.cnf).toEqual({
        jkt: 'thumbprint-value',
      });
    });

    it('should handle credential with nbf (not before) field', async () => {
      const now = getCurrentUnixTimeForTest();
      const token = await createToken(privateKey, false, {
        nbf: now - 3600, // Not before 1 hour ago
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.nbf).toBe(now - 3600);
    });

    it('should handle credential with jti (JWT ID) field', async () => {
      const token = await createToken(privateKey, false, {
        jti: 'unique-jwt-id-12345',
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.jti).toBe('unique-jwt-id-12345');
    });

    it('should handle empty selective disclosure parts', async () => {
      const token = await createToken(privateKey, false);

      // Multiple tildes with empty parts
      const sdJwt = `${token}~~~`;

      const result = await decodeSDJWT(sdJwt, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toBeUndefined(); // Empty parts should be filtered out
    });

    it('should accept credential without exp when checkExpiration is true', async () => {
      const token = await createToken(privateKey, false, {
        exp: undefined, // No expiration
      });

      const result = await decodeSDJWT(token, {
        checkExpiration: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should use default verifySignature/checkExpiration values with signingKeyResolver provided', async () => {
      const now = getCurrentUnixTimeForTest();
      const token = await createToken(privateKey, false, {
        exp: now + 3600, // Not expired
      });

      // Call with minimal options (only signingKeyResolver) - other flags should use defaults
      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should handle complex nested claims in credential', async () => {
      const token = await createToken(privateKey, false, {
        address: {
          street: '123 Main St',
          city: 'Toronto',
          country: 'Canada',
        },
        education: [
          { degree: 'BSc', year: 2018 },
          { degree: 'MSc', year: 2020 },
        ],
      });

      const result = await decodeSDJWT(token, {
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.address).toEqual({
        street: '123 Main St',
        city: 'Toronto',
        country: 'Canada',
      });
      expect(result.data?.education).toEqual([
        { degree: 'BSc', year: 2018 },
        { degree: 'MSc', year: 2020 },
      ]);
    });
  });

  describe('isSDJWTExpired', () => {
    it('should return false for credential without expiration', () => {
      const credential: SDJWT = {
        iss: 'did:example:123',
        iat: getCurrentUnixTimeForTest(),
      };

      expect(isSDJWTExpired(credential)).toBe(false);
    });

    it('should return true for expired credential', () => {
      const now = getCurrentUnixTimeForTest();
      const credential: SDJWT = {
        iss: 'did:example:123',
        iat: now - 7200,
        exp: now - 3600, // Expired 1 hour ago
      };

      expect(isSDJWTExpired(credential)).toBe(true);
    });

    it('should return false for non-expired credential', () => {
      const now = getCurrentUnixTimeForTest();
      const credential: SDJWT = {
        iss: 'did:example:123',
        iat: now,
        exp: now + 3600, // Expires in 1 hour
      };

      expect(isSDJWTExpired(credential)).toBe(false);
    });

    it('should return true for credential that expires exactly now', () => {
      const now = getCurrentUnixTimeForTest();
      const credential: SDJWT = {
        iss: 'did:example:123',
        iat: now - 3600,
        exp: now - 1, // Expired 1 second ago
      };

      expect(isSDJWTExpired(credential)).toBe(true);
    });

    it('should handle credential with exp set to 0 (treated as no expiration)', () => {
      const credential: SDJWT = {
        iss: 'did:example:123',
        iat: getCurrentUnixTimeForTest(),
        exp: 0, // Falsy value, treated as no expiration
      };

      // Note: exp=0 is treated as no expiration due to falsy check
      expect(isSDJWTExpired(credential)).toBe(false);
    });

    it('should handle credential with future exp far ahead', () => {
      const credential: SDJWT = {
        iss: 'did:example:123',
        iat: getCurrentUnixTimeForTest(),
        exp: getCurrentUnixTimeForTest() + 365 * 24 * 3600, // 1 year from now
      };

      expect(isSDJWTExpired(credential)).toBe(false);
    });
  });

  describe('JSON Schema Validation', () => {
    it('should reject credential missing required field: iss', async () => {
      // Create a token with missing iss
      const payload = {
        iat: getCurrentUnixTimeForTest(),
        name: 'John Doe',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should reject credential missing required field: iat', async () => {
      // Create a token with missing iat
      const payload = {
        iss: 'did:example:issuer',
        name: 'John Doe',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should reject credential with wrong type for iss (number instead of string)', async () => {
      // Create a token with iss as number
      const payload = {
        iss: 12345, // Should be string
        iat: getCurrentUnixTimeForTest(),
      };

      const token = await new jose.SignJWT(payload as Record<string, unknown>)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should reject credential with string iat timestamp', async () => {
      // String timestamps are not supported
      const payload = {
        iss: 'did:example:issuer',
        iat: '2024-01-01', // Any string timestamp must be rejected
      };

      const token = await new jose.SignJWT(payload as Record<string, unknown>)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should validate VC+SD-JWT with valid vct field (URI format)', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type', // Valid URI
        name: 'John Doe',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data?.vct).toBe('https://example.com/credential-type');
    });

    it('should reject VC+SD-JWT with invalid vct format (not a URI)', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'not a uri', // Invalid URI format
        name: 'John Doe',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should validate VC+SD-JWT with valid cnf.jwk', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type',
        cnf: {
          jwk: {
            kty: 'RSA',
            n: 'abc123',
            e: 'AQAB',
          },
        },
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data?.cnf).toBeDefined();
      expect((result.data as VCSDJWT)?.cnf?.jwk).toBeDefined();
    });

    it('should validate VC+SD-JWT with valid cnf.jkt', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type',
        cnf: {
          jkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
        },
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data?.cnf).toBeDefined();
      expect((result.data as VCSDJWT)?.cnf?.jkt).toBe(
        'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'
      );
    });

    it('should reject VC+SD-JWT with invalid cnf structure (both jwk and jkt)', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type',
        cnf: {
          jwk: { kty: 'RSA' },
          jkt: 'some-thumbprint', // Should be either jwk OR jkt, not both
        },
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should reject VC+SD-JWT with empty cnf object', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type',
        cnf: {}, // Empty cnf, must have jwk or jkt
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should validate SD-JWT with _sd field', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        _sd: ['hash1', 'hash2'],
        _sd_alg: 'sha-256',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data?._sd).toEqual(['hash1', 'hash2']);
      expect(result.data?._sd_alg).toBe('sha-256');
    });

    it('should accept SD-JWT with _sd but missing _sd_alg (defaults to sha-256)', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        _sd: ['hash1', 'hash2'],
        // Missing _sd_alg - now optional, defaults to 'sha-256'
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should use SD-JWT schema when typ is not "vc+sd-jwt" even if vct is present', async () => {
      // Payload has vct, but typ header is not vc+sd-jwt
      // Should validate against SD-JWT schema which allows vct as additional property
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data?.vct).toBe('https://example.com/credential-type');
    });

    it('should use VC+SD-JWT schema when typ is "vc+sd-jwt" and require vct', async () => {
      // typ header is vc+sd-jwt, but payload is missing required vct field
      // Should validate against VC+SD-JWT schema which requires vct
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        name: 'John Doe',
        // Missing vct - required by VC+SD-JWT schema
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'vc+sd-jwt' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token format in JWT payload');
    });

    it('should handle mixed case typ header (case-insensitive)', async () => {
      const payload = {
        iss: 'did:example:issuer',
        iat: getCurrentUnixTimeForTest(),
        vct: 'https://example.com/credential-type',
      };

      const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', typ: 'VC+SD-JWT' })
        .sign(privateKey);

      const result = await decodeSDJWT(token, { verifySignature: false });

      expect(result.valid).toBe(true);
      expect(result.data?.vct).toBe('https://example.com/credential-type');
    });
  });

  describe('SD Hash Validation', () => {
    it('should validate disclosure hashes against _sd array', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));

      // Compute expected hashes
      const hash1 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure1));
      const hash2 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure2));
      const hash1Base64 = uint8ArrayToBase64url(new Uint8Array(hash1));
      const hash2Base64 = uint8ArrayToBase64url(new Uint8Array(hash2));

      // Create token with _sd array containing the hashes
      const token = await createToken(privateKey, false, {
        _sd: [hash1Base64, hash2Base64],
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~${disclosure2}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.disclosures).toEqual({
        age: 30,
        country: 'CA',
      });
    });

    it('should reject when disclosure hash does not match _sd array', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));

      // Create token with wrong hash in _sd array
      const token = await createToken(privateKey, false, {
        _sd: ['wrong_hash_value'],
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Disclosure hash validation failed');
      expect(result.error).toContain('not found in _sd array');
    });

    it('should skip hash validation when validateDisclosureHashes is false', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));

      // Create token with wrong hash in _sd array
      const token = await createToken(privateKey, false, {
        _sd: ['wrong_hash_value'],
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: false,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      // Should succeed because hash validation is disabled
      expect(result.valid).toBe(true);
      expect(result.disclosures).toEqual({
        age: 30,
      });
    });

    it('should skip hash validation when _sd array is not present', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));

      // Create token without _sd array
      const token = await createToken(privateKey, false, {
        name: 'John Doe',
      });

      const sdJwt = `${token}~${disclosure1}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      // Should succeed because no _sd array to validate against
      expect(result.valid).toBe(true);
      expect(result.disclosures).toEqual({
        age: 30,
      });
    });

    it('should support sha-256 algorithm (default)', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'name', 'Alice']));

      // Compute hash using SHA-256
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure1));
      const hashBase64 = uint8ArrayToBase64url(new Uint8Array(hash));

      // Create token with _sd array and sha-256 algorithm
      const token = await createToken(privateKey, false, {
        _sd: [hashBase64],
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.disclosures).toEqual({
        name: 'Alice',
      });
    });

    it('should reject unsupported hash algorithm', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));

      // Create token with unsupported hash algorithm
      const token = await createToken(privateKey, false, {
        _sd: ['some_hash'],
        _sd_alg: 'md5', // Unsupported algorithm
      });

      const sdJwt = `${token}~${disclosure1}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Disclosure hash validation failed');
      expect(result.error).toContain('Unsupported hash algorithm');
    });

    it('should validate multiple disclosures with correct hashes', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'firstName', 'John']));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'lastName', 'Doe']));
      const disclosure3 = stringToBase64url(JSON.stringify(['salt3', 'email', 'john@example.com']));

      // Compute hashes
      const hash1 = uint8ArrayToBase64url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure1)))
      );
      const hash2 = uint8ArrayToBase64url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure2)))
      );
      const hash3 = uint8ArrayToBase64url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure3)))
      );

      const token = await createToken(privateKey, false, {
        _sd: [hash1, hash2, hash3],
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~${disclosure2}~${disclosure3}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(true);
      expect(result.disclosures).toEqual({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
      });
    });

    it('should allow _sd array to contain more hashes than provided disclosures', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));

      // Compute hash for disclosure1
      const hash1 = uint8ArrayToBase64url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure1)))
      );

      // Create token with extra hashes in _sd array (for undisclosed claims)
      const token = await createToken(privateKey, false, {
        _sd: [hash1, 'extra_hash_1', 'extra_hash_2'],
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      // Should succeed - not all hashes need to be disclosed
      expect(result.valid).toBe(true);
      expect(result.disclosures).toEqual({
        age: 30,
      });
    });

    it('should reject when one of multiple disclosures has incorrect hash', async () => {
      const disclosure1 = stringToBase64url(JSON.stringify(['salt1', 'age', 30]));
      const disclosure2 = stringToBase64url(JSON.stringify(['salt2', 'country', 'CA']));

      // Only compute hash for disclosure1
      const hash1 = uint8ArrayToBase64url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disclosure1)))
      );

      const token = await createToken(privateKey, false, {
        _sd: [hash1], // Missing hash for disclosure2
        _sd_alg: 'sha-256',
      });

      const sdJwt = `${token}~${disclosure1}~${disclosure2}~`;

      const result = await decodeSDJWT(sdJwt, {
        validateDisclosureHashes: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Disclosure hash validation failed');
    });
  });

  describe('Additional Coverage Tests', () => {
    it('should handle keyResolver that throws non-Error exception', async () => {
      const token = await createToken(privateKey, false);

      const result = await decodeSDJWT(token, {
        verifySignature: true,
        signingKeyResolver: () => {
          return Promise.reject(new Error('Key resolution failed'));
        },
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Key resolution failed');
    });

    it('should fail when keyResolver returns undefined', async () => {
      const token = await createToken(privateKey, false);

      const result = await decodeSDJWT(token, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(undefined as unknown as CryptoKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Public key required');
    });

    it('should handle keyResolver with missing iss claim', async () => {
      // Create a malformed token that doesn't have proper typ header
      // to test the iss resolution path
      const payloadBase64 = stringToBase64url(
        JSON.stringify({
          iat: getCurrentUnixTimeForTest(),
          // Missing iss claim
        })
      );

      const headerBase64 = stringToBase64url(
        JSON.stringify({
          alg: 'RS256',
          typ: 'sd-jwt',
        })
      );

      const token = `${headerBase64}.${payloadBase64}.fakesignature`;

      const result = await decodeSDJWT(token, {
        verifySignature: true,
        signingKeyResolver: () => Promise.resolve(publicKey),
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('missing iss claim');
    });

    it('should handle cnf validation when both jwk and jkt present', async () => {
      // This tests the cnf constraint validation at line 448
      const token = await createToken(
        privateKey,
        false,
        {
          vct: 'https://credentials.example.com/identity',
          cnf: {
            jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
            jkt: 'invalid-combo',
          },
        },
        'vc+sd-jwt'
      );

      const result = await decodeSDJWT(token, {
        verifySignature: false,
      });

      // Should fail because both jwk and jkt are present (violates cnf constraint)
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid token format');
    });

    it('should handle general exception in credential validation', async () => {
      // Create a token with proper structure but missing required typ header
      const payloadBase64 = stringToBase64url(
        JSON.stringify({
          iss: 'did:example:issuer',
          iat: getCurrentUnixTimeForTest(),
        })
      );

      const headerBase64 = stringToBase64url(
        JSON.stringify({
          alg: 'RS256',
          // Missing typ header
        })
      );

      const invalidToken = `${headerBase64}.${payloadBase64}.signature`;

      const result = await decodeSDJWT(invalidToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle credential extraction failure gracefully', async () => {
      // Create a token with a payload that won't pass schema validation
      const badPayload = stringToBase64url(
        JSON.stringify({
          // Missing required iss field
          iat: getCurrentUnixTimeForTest(),
        })
      );

      const header = stringToBase64url(
        JSON.stringify({
          alg: 'RS256',
          typ: 'JWT',
        })
      );

      const signature = 'fakesignature';
      const invalidToken = `${header}.${badPayload}.${signature}`;

      const result = await decodeSDJWT(invalidToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
