import { generateKeyPairSync } from 'crypto';
import { verify } from 'jsonwebtoken';

// Generate a test RSA key pair
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Mock fs.readFileSync BEFORE importing the service
jest.mock('fs', () => ({
  readFileSync: jest.fn(),
}));

import { readFileSync } from 'fs';
import { FederationTokenService } from '../federation-token.service';

const mockedReadFileSync = readFileSync as jest.MockedFunction<typeof readFileSync>;

function makeMockConfigService(overrides: Record<string, any> = {}) {
  const defaults: Record<string, any> = {
    FEDERATION_PRIVATE_KEY_PATH: '/fake/path/private.pem',
    ...overrides,
  };
  return {
    get: jest.fn((key: string) => defaults[key] ?? undefined),
  };
}

describe('FederationTokenService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedReadFileSync.mockReturnValue(privateKey);
  });

  // --- Constructor tests ---

  it('should throw if FEDERATION_PRIVATE_KEY_PATH is not set', () => {
    const configService = makeMockConfigService({
      FEDERATION_PRIVATE_KEY_PATH: undefined,
    });

    expect(() => new FederationTokenService(configService as any)).toThrow(
      'FEDERATION_PRIVATE_KEY_PATH env var is not set',
    );
  });

  it('should throw if the private key file is not readable', () => {
    mockedReadFileSync.mockImplementation(() => {
      throw new Error('ENOENT: no such file or directory');
    });

    const configService = makeMockConfigService();

    expect(() => new FederationTokenService(configService as any)).toThrow(
      'Failed to read federation private key',
    );
  });

  it('should construct successfully with a valid key path', () => {
    const configService = makeMockConfigService();

    expect(() => new FederationTokenService(configService as any)).not.toThrow();
    expect(mockedReadFileSync).toHaveBeenCalledWith('/fake/path/private.pem', 'utf8');
  });

  // --- getToken() tests ---

  it('should return a valid JWT string', async () => {
    const configService = makeMockConfigService();
    const service = new FederationTokenService(configService as any);

    const token = await service.getToken();

    expect(typeof token).toBe('string');
    // JWT format: three dot-separated base64url segments
    expect(token.split('.')).toHaveLength(3);
  });

  it('should return a JWT with correct iss and sub claims', async () => {
    const configService = makeMockConfigService();
    const service = new FederationTokenService(configService as any);

    const token = await service.getToken();
    const decoded = verify(token, publicKey, { algorithms: ['RS256'] }) as any;

    expect(decoded.iss).toBe('cucu-gateway');
    expect(decoded.sub).toBe('federation');
  });

  it('should return a JWT with exp ~60s in the future', async () => {
    const configService = makeMockConfigService();
    const service = new FederationTokenService(configService as any);

    const beforeSec = Math.floor(Date.now() / 1000);
    const token = await service.getToken();
    const afterSec = Math.floor(Date.now() / 1000);

    const decoded = verify(token, publicKey, { algorithms: ['RS256'] }) as any;

    // exp should be iat + 60. iat is between beforeSec and afterSec.
    expect(decoded.exp).toBeGreaterThanOrEqual(beforeSec + 60);
    expect(decoded.exp).toBeLessThanOrEqual(afterSec + 60);
  });

  it('should cache the token on subsequent calls', async () => {
    const configService = makeMockConfigService();
    const service = new FederationTokenService(configService as any);

    // Pin Date.now so the first call uses a known time
    const baseTime = Date.now();
    const dateNowSpy = jest.spyOn(Date, 'now');
    dateNowSpy.mockReturnValue(baseTime);

    const token1 = await service.getToken();

    // Advance by 2 seconds — still well within cache window,
    // but iat would differ if a new token were signed (floor division changes).
    // If caching is broken, sign() would use a different iat → different JWT.
    dateNowSpy.mockReturnValue(baseTime + 2_000);

    const token2 = await service.getToken();

    expect(token1).toBe(token2);
    dateNowSpy.mockRestore();
  });

  it('should regenerate the token when < 10s from expiry', async () => {
    const configService = makeMockConfigService();
    const service = new FederationTokenService(configService as any);

    // Fix Date.now to a known value for the first call
    const baseTime = Date.now();
    const dateNowSpy = jest.spyOn(Date, 'now');
    dateNowSpy.mockReturnValue(baseTime);

    const token1 = await service.getToken();

    // Advance time by 55 seconds — only 5s left before expiry (< 10s threshold)
    dateNowSpy.mockReturnValue(baseTime + 55_000);

    const token2 = await service.getToken();

    expect(token2).not.toBe(token1);
    // New token should still be valid
    const decoded = verify(token2, publicKey, { algorithms: ['RS256'] }) as any;
    expect(decoded.iss).toBe('cucu-gateway');

    dateNowSpy.mockRestore();
  });
});
