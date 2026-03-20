import { ConfigService } from '@nestjs/config';
export declare class FederationTokenService {
    private readonly configService;
    private readonly log;
    private readonly privateKey;
    private cachedToken;
    private expiresAt;
    constructor(configService: ConfigService);
    getToken(): Promise<string>;
}
