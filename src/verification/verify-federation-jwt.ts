import { readFileSync } from 'fs';
import { verify } from 'jsonwebtoken';

/** Cached public key (read once from file) */
let _federationPublicKey: string | null = null;

/**
 * Loads the federation public key from the path specified in
 * FEDERATION_PUBLIC_KEY_PATH. Caches in memory after first read.
 * Returns null if the env var is not set or the file can't be read.
 */
function loadFederationPublicKey(): string | null {
  if (_federationPublicKey !== null) return _federationPublicKey;

  const keyPath = process.env.FEDERATION_PUBLIC_KEY_PATH;
  if (!keyPath) return null;

  try {
    _federationPublicKey = readFileSync(keyPath, 'utf8');
    return _federationPublicKey;
  } catch {
    return null;
  }
}

/**
 * Verifies a federation JWT signed by the gateway using RS256.
 *
 * Checks:
 * - Signature validity (RS256)
 * - Expiration (`exp`)
 * - Issuer (`iss === 'cucu-gateway'`)
 * - Subject (`sub === 'federation'`)
 *
 * Returns true if valid, false otherwise.
 * Does NOT throw — all errors are caught and result in false.
 */
export function verifyFederationJwt(token: string): boolean {
  const publicKey = loadFederationPublicKey();
  if (!publicKey) return false;

  try {
    const decoded: any = verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: 'cucu-gateway',
    });
    // Extra safety: verify subject
    if (decoded.sub !== 'federation') return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Resets the cached public key. Useful for testing.
 * @internal
 */
export function _resetFederationKeyCache(): void {
  _federationPublicKey = null;
}
