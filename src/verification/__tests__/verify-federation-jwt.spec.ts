import { generateKeyPairSync } from 'crypto';
import { sign } from 'jsonwebtoken';

// Generate a test RSA key pair
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Generate a second key pair for "wrong key" tests
const { privateKey: wrongPrivateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Mock fs.readFileSync BEFORE importing the function
jest.mock('fs', () => ({
  readFileSync: jest.fn(),
}));

import { readFileSync } from 'fs';
import {
  verifyFederationJwt,
  _resetFederationKeyCache,
} from '../verify-federation-jwt';

const mockedReadFileSync = readFileSync as jest.MockedFunction<typeof readFileSync>;

/** Signs a test JWT with the given overrides */
function signTestToken(
  overrides: {
    key?: string;
    iss?: string;
    sub?: string;
    expiresIn?: number;
  } = {},
): string {
  const { key = privateKey, iss = 'cucu-gateway', sub = 'federation', expiresIn = 60 } = overrides;
  return sign(
    { iss, sub, iat: Math.floor(Date.now() / 1000) },
    key,
    { algorithm: 'RS256', expiresIn },
  );
}

describe('verifyFederationJwt', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    _resetFederationKeyCache();
    process.env.FEDERATION_PUBLIC_KEY_PATH = '/fake/path/public.pem';
    mockedReadFileSync.mockReturnValue(publicKey);
  });

  afterEach(() => {
    delete process.env.FEDERATION_PUBLIC_KEY_PATH;
    _resetFederationKeyCache();
  });

  it('should return true for a valid token signed with the matching private key', () => {
    const token = signTestToken();
    expect(verifyFederationJwt(token)).toBe(true);
  });

  it('should return false for a token signed with a different key', () => {
    const token = signTestToken({ key: wrongPrivateKey });
    expect(verifyFederationJwt(token)).toBe(false);
  });

  it('should return false for an expired token', () => {
    // Sign a token that expired 10 seconds ago
    const token = sign(
      {
        iss: 'cucu-gateway',
        sub: 'federation',
        iat: Math.floor(Date.now() / 1000) - 70,
      },
      privateKey,
      { algorithm: 'RS256', expiresIn: 60 },
    );
    expect(verifyFederationJwt(token)).toBe(false);
  });

  it('should return false for a token with the wrong issuer', () => {
    const token = signTestToken({ iss: 'evil-gateway' });
    expect(verifyFederationJwt(token)).toBe(false);
  });

  it('should return false for a token with the wrong subject', () => {
    const token = signTestToken({ sub: 'admin' });
    expect(verifyFederationJwt(token)).toBe(false);
  });

  it('should return false for a malformed/garbage token', () => {
    expect(verifyFederationJwt('not.a.jwt')).toBe(false);
    expect(verifyFederationJwt('')).toBe(false);
    expect(verifyFederationJwt('garbage')).toBe(false);
  });

  it('should return false when FEDERATION_PUBLIC_KEY_PATH is not set', () => {
    delete process.env.FEDERATION_PUBLIC_KEY_PATH;
    _resetFederationKeyCache();

    const token = signTestToken();
    expect(verifyFederationJwt(token)).toBe(false);
  });

  it('should return false when the public key file is not readable', () => {
    mockedReadFileSync.mockImplementation(() => {
      throw new Error('ENOENT: no such file or directory');
    });
    _resetFederationKeyCache();

    const token = signTestToken();
    expect(verifyFederationJwt(token)).toBe(false);
  });
});
