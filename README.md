# @cucu/security

Security utilities for Cucu microservices — HMAC header verification, federation JWT signing & verification.

## Installation

```bash
npm install github:CucuProject/security
```

## Exports

### Verification

- **`verifyGatewaySignature(headers)`** — Verifies HMAC-SHA256 signature on internal gateway headers. Reads `INTERNAL_HEADER_SECRET` from env. Returns `false` if secret is not set.
- **`verifyFederationJwt(token)`** — Verifies RS256 federation JWT. Reads public key from `FEDERATION_PUBLIC_KEY_PATH` env var, caches in memory. Checks `exp`, `iss === 'cucu-gateway'`, `sub === 'federation'`.

### Signing

- **`FederationTokenService`** — NestJS `@Injectable()` service that signs RS256 federation JWTs. Reads private key from `FEDERATION_PRIVATE_KEY_PATH`. Caches tokens with 10s margin before 60s TTL expiry.

## Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `INTERNAL_HEADER_SECRET` | `verifyGatewaySignature` | Shared HMAC secret between gateway and subgraphs |
| `FEDERATION_PUBLIC_KEY_PATH` | `verifyFederationJwt` | Path to RSA public key (PEM) |
| `FEDERATION_PRIVATE_KEY_PATH` | `FederationTokenService` | Path to RSA private key (PEM) |
