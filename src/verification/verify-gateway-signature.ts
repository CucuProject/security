import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Verifies that internal headers were set by the gateway, not spoofed.
 * Returns true if the HMAC-SHA256 signature matches, false otherwise.
 *
 * The gateway computes: HMAC( x-user-groups | x-internal-federation-call | x-user-id | x-tenant-slug | x-tenant-id )
 * and sends it as x-gateway-signature.
 *
 * If INTERNAL_HEADER_SECRET is not set, returns false (rejects).
 * No fallback default — the secret MUST be explicitly configured.
 */
export function verifyGatewaySignature(headers: Record<string, any>): boolean {
  const signature = (headers['x-gateway-signature'] ?? '').toString();
  if (!signature) return false;

  const secret = process.env.INTERNAL_HEADER_SECRET;
  if (!secret) return false;

  const userGroups = (headers['x-user-groups'] ?? '').toString();
  const internalCall = (headers['x-internal-federation-call'] ?? '').toString();
  const userId = (headers['x-user-id'] ?? '').toString();
  const tenantSlug = (headers['x-tenant-slug'] ?? '').toString();
  const tenantId = (headers['x-tenant-id'] ?? '').toString();
  const payload = `${userGroups}|${internalCall}|${userId}|${tenantSlug}|${tenantId}`;
  const expected = createHmac('sha256', secret).update(payload).digest('hex');

  // Timing-safe comparison to prevent timing attacks
  if (signature.length !== expected.length) return false;
  const sigBuf = new Uint8Array(Buffer.from(signature, 'utf8'));
  const expBuf = new Uint8Array(Buffer.from(expected, 'utf8'));
  return timingSafeEqual(sigBuf, expBuf);
}
