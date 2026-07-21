import { reconstructSDJWT } from './reconstruct';
import { decodeSDJWT } from '../sdjwt';

jest.mock('../sdjwt', () => ({
  decodeSDJWT: jest.fn(),
}));

const mockedDecodeSDJWT = decodeSDJWT as jest.MockedFunction<typeof decodeSDJWT>;

describe('SD-JWT Reconstruct', () => {
  const jwt = 'header.payload.signature';
  const disclosureAge = 'disc-age';
  const disclosureCountry = 'disc-country';
  const disclosureName = 'disc-name';

  beforeEach(() => {
    mockedDecodeSDJWT.mockReset();
  });

  describe('reconstructSDJWT', () => {
    it('reconstructs with selected disclosures', async () => {
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: {
          age: disclosureAge,
          country: disclosureCountry,
          name: disclosureName,
        },
      });

      const result = await reconstructSDJWT('unused-input', ['age', 'country']);

      expect(result.valid).toBe(true);
      expect(result.token).toBe(`${jwt}~${disclosureAge}~${disclosureCountry}`);
      expect(result.token).not.toContain(disclosureName);
    });

    it('returns jwt only when no claim names match', async () => {
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: { age: disclosureAge },
      });

      const result = await reconstructSDJWT('unused-input', ['nonexistent']);

      expect(result.valid).toBe(true);
      expect(result.token).toBe(jwt);
    });

    it('returns jwt only when claim names array is empty', async () => {
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: { age: disclosureAge },
      });

      const result = await reconstructSDJWT('unused-input', []);

      expect(result.valid).toBe(true);
      expect(result.token).toBe(jwt);
    });

    it('includes attestation when provided', async () => {
      const attestation = 'attestation-proof';
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: { age: disclosureAge },
      });

      const result = await reconstructSDJWT('unused-input', ['age'], attestation);

      expect(result.valid).toBe(true);
      expect(result.token).toBe(`${jwt}~${disclosureAge}~${attestation}`);
    });

    it('keeps attestation as last segment when claim names are empty', async () => {
      const attestation = 'attestation-proof';
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: { age: disclosureAge },
      });

      const result = await reconstructSDJWT('unused-input', [], attestation);

      expect(result.valid).toBe(true);
      expect(result.token).toBe(`${jwt}~${attestation}`);
    });

    it('ignores empty attestation string', async () => {
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: { age: disclosureAge },
      });

      const result = await reconstructSDJWT('unused-input', ['age'], '');

      expect(result.valid).toBe(true);
      expect(result.token).toBe(`${jwt}~${disclosureAge}`);
    });

    it('returns jwt when disclosures are unavailable', async () => {
      mockedDecodeSDJWT.mockResolvedValue({
        valid: true,
        rawData: jwt,
        rawDisclosures: undefined,
      });

      const result = await reconstructSDJWT('unused-input', ['age']);

      expect(result.valid).toBe(true);
      expect(result.token).toBe(jwt);
    });

    it('wraps decode errors', async () => {
      mockedDecodeSDJWT.mockRejectedValue(new Error('Credential token is required'));

      const result = await reconstructSDJWT('unused-input', ['age']);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Failed to reconstruct SD-JWT: Credential token is required');
    });
  });
});
