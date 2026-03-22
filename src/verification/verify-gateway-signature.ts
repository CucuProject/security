import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Verifies that internal headers were set by the gateway, not spoofed.
 * Returns true if the HMAC-SHA256 signature matches, false otherwise.
 *
 * The gateway computes: HMAC( x-user-groups | x-internal-federation-call | x-user-id | x-tenant-slug | x-tenant-id | x-gateway-timestamp )
 * and sends it as x-gateway-signature.
 *
 * The timestamp (milliseconds since epoch) is included in the HMAC payload
 * to prevent replay attacks. Requests older than 30 seconds are rejected.
 *
 * If INTERNAL_HEADER_SECRET is not set, returns false (rejects).
 * No fallback default — the secret MUST be explicitly configured.
 */
export function verifyGatewaySignature(headers: Record<string, any>): boolean {
  const signature = (headers['x-gateway-signature'] ?? '').toString();
  if (!signature) return false;

  const secret = process.env.INTERNAL_HEADER_SECRET;
  if (!secret) return false;

  // Check timestamp freshness (reject if > 30 seconds old)
  const timestamp = (headers['x-gateway-timestamp'] ?? '').toString();
  if (!timestamp) return false;
  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age < 0 || age > 30000) return false;

  const userGroups = (headers['x-user-groups'] ?? '').toString();
  const internalCall = (headers['x-internal-federation-call'] ?? '').toString();
  const userId = (headers['x-user-id'] ?? '').toString();
  const tenantSlug = (headers['x-tenant-slug'] ?? '').toString();
  const tenantId = (headers['x-tenant-id'] ?? '').toString();
  const payload = `${userGroups}|${internalCall}|${userId}|${tenantSlug}|${tenantId}|${timestamp}`;
  const expected = createHmac('sha256', secret).update(payload).digest('hex');

  // Timing-safe comparison to prevent timing attacks
  if (signature.length !== expected.length) return false;
  const sigBuf = new Uint8Array(Buffer.from(signature, 'utf8'));
  const expBuf = new Uint8Array(Buffer.from(expected, 'utf8'));
  return timingSafeEqual(sigBuf, expBuf);
}
