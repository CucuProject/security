"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyFederationJwt = verifyFederationJwt;
exports._resetFederationKeyCache = _resetFederationKeyCache;
const fs_1 = require("fs");
const jsonwebtoken_1 = require("jsonwebtoken");
let _federationPublicKey = null;
function loadFederationPublicKey() {
    if (_federationPublicKey !== null)
        return _federationPublicKey;
    const keyPath = process.env.FEDERATION_PUBLIC_KEY_PATH;
    if (!keyPath)
        return null;
    try {
        _federationPublicKey = (0, fs_1.readFileSync)(keyPath, 'utf8');
        return _federationPublicKey;
    }
    catch (_a) {
        return null;
    }
}
function verifyFederationJwt(token) {
    const publicKey = loadFederationPublicKey();
    if (!publicKey)
        return false;
    try {
        const decoded = (0, jsonwebtoken_1.verify)(token, publicKey, {
            algorithms: ['RS256'],
            issuer: 'cucu-gateway',
        });
        if (decoded.sub !== 'federation')
            return false;
        return true;
    }
    catch (_a) {
        return false;
    }
}
function _resetFederationKeyCache() {
    _federationPublicKey = null;
}
