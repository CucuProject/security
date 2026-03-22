import { createHmac } from 'crypto';
import { verifyGatewaySignature } from './verify-gateway-signature';

const SECRET = 'test-secret-key-for-hmac';

function makeHeaders(overrides: Record<string, string> = {}, timestampOverride?: string) {
  const timestamp = timestampOverride ?? Date.now().toString();
  const headers: Record<string, string> = {
    'x-user-groups': 'admin,user',
    'x-internal-federation-call': '1',
    'x-user-id': 'user-123',
    'x-tenant-slug': 'acme',
    'x-tenant-id': 'tenant-456',
    'x-gateway-timestamp': timestamp,
    ...overrides,
  };

  // Compute valid signature
  const payload = `${headers['x-user-groups']}|${headers['x-internal-federation-call']}|${headers['x-user-id']}|${headers['x-tenant-slug']}|${headers['x-tenant-id']}|${headers['x-gateway-timestamp']}`;
  headers['x-gateway-signature'] = createHmac('sha256', SECRET)
    .update(payload)
    .digest('hex');

  return headers;
}

describe('verifyGatewaySignature', () => {
  beforeEach(() => {
    process.env.INTERNAL_HEADER_SECRET = SECRET;
  });

  afterEach(() => {
    delete process.env.INTERNAL_HEADER_SECRET;
  });

  it('should return true for a valid signature with fresh timestamp', () => {
    const headers = makeHeaders();
    expect(verifyGatewaySignature(headers)).toBe(true);
  });

  it('should return true for a timestamp just under 30s old', () => {
    const timestamp = (Date.now() - 29000).toString();
    const headers = makeHeaders({}, timestamp);
    expect(verifyGatewaySignature(headers)).toBe(true);
  });

  it('should return false for an expired timestamp (> 30s old)', () => {
    const timestamp = (Date.now() - 31000).toString();
    const headers = makeHeaders({}, timestamp);
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false when timestamp is missing', () => {
    const headers = makeHeaders();
    delete headers['x-gateway-timestamp'];

    // Re-sign without timestamp (old format) — should still fail
    const payload = `${headers['x-user-groups']}|${headers['x-internal-federation-call']}|${headers['x-user-id']}|${headers['x-tenant-slug']}|${headers['x-tenant-id']}`;
    headers['x-gateway-signature'] = createHmac('sha256', SECRET)
      .update(payload)
      .digest('hex');

    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false for a timestamp in the future (negative age)', () => {
    const timestamp = (Date.now() + 5000).toString();
    const headers = makeHeaders({}, timestamp);
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false for a non-numeric timestamp', () => {
    const headers = makeHeaders({}, 'not-a-number');
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false for old format signature without timestamp (backward incompatible, intentional)', () => {
    // Simulate old gateway: signs without timestamp
    const headers: Record<string, string> = {
      'x-user-groups': 'admin,user',
      'x-internal-federation-call': '1',
      'x-user-id': 'user-123',
      'x-tenant-slug': 'acme',
      'x-tenant-id': 'tenant-456',
    };
    const payload = `${headers['x-user-groups']}|${headers['x-internal-federation-call']}|${headers['x-user-id']}|${headers['x-tenant-slug']}|${headers['x-tenant-id']}`;
    headers['x-gateway-signature'] = createHmac('sha256', SECRET)
      .update(payload)
      .digest('hex');

    // No x-gateway-timestamp header at all
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false when signature is missing', () => {
    const headers = makeHeaders();
    delete headers['x-gateway-signature'];
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false when secret is not set', () => {
    delete process.env.INTERNAL_HEADER_SECRET;
    const headers = makeHeaders();
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false for a tampered signature', () => {
    const headers = makeHeaders();
    headers['x-gateway-signature'] = 'deadbeef'.repeat(8); // 64 hex chars, same length
    expect(verifyGatewaySignature(headers)).toBe(false);
  });

  it('should return false when a header value is tampered after signing', () => {
    const headers = makeHeaders();
    headers['x-user-id'] = 'attacker-id';
    expect(verifyGatewaySignature(headers)).toBe(false);
  });
});
