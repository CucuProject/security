"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyGatewaySignature = verifyGatewaySignature;
const crypto_1 = require("crypto");
function verifyGatewaySignature(headers) {
    var _a, _b, _c, _d, _e, _f, _g;
    const signature = ((_a = headers['x-gateway-signature']) !== null && _a !== void 0 ? _a : '').toString();
    if (!signature)
        return false;
    const secret = process.env.INTERNAL_HEADER_SECRET;
    if (!secret)
        return false;
    const timestamp = ((_b = headers['x-gateway-timestamp']) !== null && _b !== void 0 ? _b : '').toString();
    if (!timestamp)
        return false;
    const age = Date.now() - parseInt(timestamp, 10);
    if (isNaN(age) || age < 0 || age > 30000)
        return false;
    const userGroups = ((_c = headers['x-user-groups']) !== null && _c !== void 0 ? _c : '').toString();
    const internalCall = ((_d = headers['x-internal-federation-call']) !== null && _d !== void 0 ? _d : '').toString();
    const userId = ((_e = headers['x-user-id']) !== null && _e !== void 0 ? _e : '').toString();
    const tenantSlug = ((_f = headers['x-tenant-slug']) !== null && _f !== void 0 ? _f : '').toString();
    const tenantId = ((_g = headers['x-tenant-id']) !== null && _g !== void 0 ? _g : '').toString();
    const payload = `${userGroups}|${internalCall}|${userId}|${tenantSlug}|${tenantId}|${timestamp}`;
    const expected = (0, crypto_1.createHmac)('sha256', secret).update(payload).digest('hex');
    if (signature.length !== expected.length)
        return false;
    const sigBuf = new Uint8Array(Buffer.from(signature, 'utf8'));
    const expBuf = new Uint8Array(Buffer.from(expected, 'utf8'));
    return (0, crypto_1.timingSafeEqual)(sigBuf, expBuf);
}
