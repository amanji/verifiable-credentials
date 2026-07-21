import type { FederationDiscoveryOptions } from './types';
import { createLocalChainFixture } from './test-utils';
import { parseEntityStatementJwt, verifyTrustChain } from './verification';

describe('openid-federation verification internals', () => {
  it('verifies a valid trust chain and returns normalized result', async () => {
    const fixture = await createLocalChainFixture({
      leafEntityId: 'https://rp.example.org',
      trustAnchorId: 'https://ta.example.org',
    });

    const options: FederationDiscoveryOptions = {};

    const result = await verifyTrustChain(
      [
        fixture.leafEntityConfigJwt,
        fixture.subordinateStatementJwt,
        fixture.trustAnchorEntityConfigJwt,
      ],
      [fixture.trustAnchorId],
      options
    );

    expect(result.trustAnchor).toBe(fixture.trustAnchorId);
    expect(result.statements).toHaveLength(3);
    expect(result.statements[0].payload.sub).toBe(fixture.leafEntityId);
    expect(result.expiresAt).toBe(fixture.now + 3600);
  });

  it('fails trust chain verification when trust anchor is not trusted', async () => {
    const fixture = await createLocalChainFixture({
      leafEntityId: 'https://rp-untrusted.example.org',
      trustAnchorId: 'https://ta-untrusted.example.org',
    });

    const options: FederationDiscoveryOptions = {};

    await expect(
      verifyTrustChain(
        [
          fixture.leafEntityConfigJwt,
          fixture.subordinateStatementJwt,
          fixture.trustAnchorEntityConfigJwt,
        ],
        [],
        options
      )
    ).rejects.toThrow('is not trusted');
  });

  it('rejects chain when first statement issuer does not match second statement subject', async () => {
    const fixture = await createLocalChainFixture({
      overrideLeafPayload: { iss: 'https://unexpected-issuer.example.org' },
    });

    await expect(
      verifyTrustChain(
        [
          fixture.leafEntityConfigJwt,
          fixture.subordinateStatementJwt,
          fixture.trustAnchorEntityConfigJwt,
        ],
        [fixture.trustAnchorId],
        {}
      )
    ).rejects.toThrow('first statement issuer must match the second statement subject');
  });

  it('rejects chain with future iat beyond skew window', async () => {
    const baseNow = 1_800_000_000;
    const fixture = await createLocalChainFixture({
      now: baseNow,
      overrideSubordinatePayload: { iat: baseNow + 120 },
    });

    await expect(
      verifyTrustChain(
        [
          fixture.leafEntityConfigJwt,
          fixture.subordinateStatementJwt,
          fixture.trustAnchorEntityConfigJwt,
        ],
        [fixture.trustAnchorId],
        { now: () => baseNow, clockSkewSeconds: 30 }
      )
    ).rejects.toThrow('iat is in the future');
  });

  it('rejects chain with expired statements', async () => {
    const baseNow = 1_900_000_000;
    const fixture = await createLocalChainFixture({
      now: baseNow - 4000,
      overrideSubordinatePayload: { exp: baseNow - 120 },
    });

    await expect(
      verifyTrustChain(
        [
          fixture.leafEntityConfigJwt,
          fixture.subordinateStatementJwt,
          fixture.trustAnchorEntityConfigJwt,
        ],
        [fixture.trustAnchorId],
        { now: () => baseNow, clockSkewSeconds: 30 }
      )
    ).rejects.toThrow('Entity statement expired');
  });

  it('rejects invalid chain continuity', async () => {
    const fixture = await createLocalChainFixture({
      overrideSubordinatePayload: { iss: 'https://wrong-issuer.example.org' },
    });

    await expect(
      verifyTrustChain(
        [
          fixture.leafEntityConfigJwt,
          fixture.subordinateStatementJwt,
          fixture.trustAnchorEntityConfigJwt,
        ],
        [fixture.trustAnchorId],
        {}
      )
    ).rejects.toThrow('Invalid chain continuity');
  });

  it('rejects invalid JWT typ values during parsing', async () => {
    const fixture = await createLocalChainFixture({
      leafEntityId: 'https://issuer.example.org',
      leafTyp: 'not-entity-statement',
    });

    expect(() => parseEntityStatementJwt(fixture.leafEntityConfigJwt)).toThrow('Invalid JWT typ');
  });
});
