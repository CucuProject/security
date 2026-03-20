"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyGatewaySignature = verifyGatewaySignature;
const crypto_1 = require("crypto");
function verifyGatewaySignature(headers) {
    var _a, _b, _c, _d, _e, _f;
    const signature = ((_a = headers['x-gateway-signature']) !== null && _a !== void 0 ? _a : '').toString();
    if (!signature)
        return false;
    const secret = process.env.INTERNAL_HEADER_SECRET;
    if (!secret)
        return false;
    const userGroups = ((_b = headers['x-user-groups']) !== null && _b !== void 0 ? _b : '').toString();
    const internalCall = ((_c = headers['x-internal-federation-call']) !== null && _c !== void 0 ? _c : '').toString();
    const userId = ((_d = headers['x-user-id']) !== null && _d !== void 0 ? _d : '').toString();
    const tenantSlug = ((_e = headers['x-tenant-slug']) !== null && _e !== void 0 ? _e : '').toString();
    const tenantId = ((_f = headers['x-tenant-id']) !== null && _f !== void 0 ? _f : '').toString();
    const payload = `${userGroups}|${internalCall}|${userId}|${tenantSlug}|${tenantId}`;
    const expected = (0, crypto_1.createHmac)('sha256', secret).update(payload).digest('hex');
    if (signature.length !== expected.length)
        return false;
    const sigBuf = new Uint8Array(Buffer.from(signature, 'utf8'));
    const expBuf = new Uint8Array(Buffer.from(expected, 'utf8'));
    return (0, crypto_1.timingSafeEqual)(sigBuf, expBuf);
}
