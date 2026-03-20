"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FederationTokenService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const fs_1 = require("fs");
const jsonwebtoken_1 = require("jsonwebtoken");
let FederationTokenService = class FederationTokenService {
    constructor(configService) {
        this.configService = configService;
        this.log = new common_1.Logger('FederationTokenService');
        this.cachedToken = '';
        this.expiresAt = 0;
        const keyPath = this.configService.get('FEDERATION_PRIVATE_KEY_PATH');
        if (!keyPath) {
            throw new Error('FEDERATION_PRIVATE_KEY_PATH env var is not set. ' +
                'Gateway cannot sign federation JWTs without a private key.');
        }
        try {
            this.privateKey = (0, fs_1.readFileSync)(keyPath, 'utf8');
        }
        catch (err) {
            throw new Error(`Failed to read federation private key from "${keyPath}": ${err}`);
        }
        this.log.log(`Federation private key loaded from ${keyPath}`);
    }
    async getToken() {
        const now = Date.now();
        if (this.cachedToken && now < this.expiresAt - 10000) {
            return this.cachedToken;
        }
        const iatSec = Math.floor(now / 1000);
        const ttl = 60;
        this.cachedToken = (0, jsonwebtoken_1.sign)({
            iss: 'cucu-gateway',
            sub: 'federation',
            iat: iatSec,
        }, this.privateKey, {
            algorithm: 'RS256',
            expiresIn: ttl,
        });
        this.expiresAt = now + ttl * 1000;
        return this.cachedToken;
    }
};
exports.FederationTokenService = FederationTokenService;
exports.FederationTokenService = FederationTokenService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [config_1.ConfigService])
], FederationTokenService);
