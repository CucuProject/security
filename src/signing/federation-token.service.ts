import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { readFileSync } from 'fs';
import { sign } from 'jsonwebtoken';

/**
 * Generates self-signed federation JWTs using an RSA private key (RS256).
 * Replaces the previous Keycloak M2M client_credentials flow.
 *
 * The private key is read once at startup from the path specified in
 * FEDERATION_PRIVATE_KEY_PATH. If the env var or file is missing, the
 * service throws immediately — no fallback, no default.
 */
@Injectable()
export class FederationTokenService {
  private readonly log = new Logger('FederationTokenService');
  private readonly privateKey: string;

  private cachedToken = '';
  private expiresAt = 0; // epoch ms

  constructor(private readonly configService: ConfigService) {
    const keyPath = this.configService.get<string>('FEDERATION_PRIVATE_KEY_PATH');
    if (!keyPath) {
      throw new Error(
        'FEDERATION_PRIVATE_KEY_PATH env var is not set. ' +
        'Gateway cannot sign federation JWTs without a private key.',
      );
    }

    try {
      this.privateKey = readFileSync(keyPath, 'utf8');
    } catch (err) {
      throw new Error(
        `Failed to read federation private key from "${keyPath}": ${err}`,
      );
    }

    this.log.log(`Federation private key loaded from ${keyPath}`);
  }

  /**
   * Returns a cached self-signed JWT, regenerating when < 10s from expiry.
   * Interface is identical to the old Keycloak-based getToken() so callers
   * (federation-request.options.ts) require no changes.
   */
  async getToken(): Promise<string> {
    const now = Date.now();
    if (this.cachedToken && now < this.expiresAt - 10_000) {
      return this.cachedToken;
    }

    const iatSec = Math.floor(now / 1000);
    const ttl = 60; // seconds

    this.cachedToken = sign(
      {
        iss: 'cucu-gateway',
        sub: 'federation',
        iat: iatSec,
      },
      this.privateKey,
      {
        algorithm: 'RS256',
        expiresIn: ttl,
      },
    );

    this.expiresAt = now + ttl * 1000;
    return this.cachedToken;
  }
}
