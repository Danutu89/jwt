import { algorithmMap, typeMap } from "../index.js";
async function verify(input, key, method, type, signature) {
    if (!input || !key || !method || !type || !signature) {
        return false;
    }
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    try {
        if (type === "hmac") {
            const algorithm = { name: algorithmMap[method].name, hash: algorithmMap[method].hash };
            const cryptoKey = await window.crypto.subtle.importKey("raw", encoder.encode(key), algorithm, false, ["sign", "verify"]);
            const signatureArray = base64ToUint8Array(base64urlUnescape(signature));
            return await window.crypto.subtle.verify(algorithm, cryptoKey, signatureArray, data);
        }
        else if (type === "sign") {
            try {
                let pemKey = key.trim();
                if (!pemKey.includes('BEGIN PUBLIC KEY')) {
                    pemKey = `-----BEGIN PUBLIC KEY-----\n${pemKey}\n-----END PUBLIC KEY-----`;
                }
                const publicKeyDER = pemKey
                    .replace(/-----BEGIN PUBLIC KEY-----/, '')
                    .replace(/-----END PUBLIC KEY-----/, '')
                    .replace(/\s/g, '');
                const publicKey = await window.crypto.subtle.importKey("spki", base64ToUint8Array(publicKeyDER), { name: algorithmMap[method].name, hash: algorithmMap[method].hash }, false, ["verify"]);
                const signatureArray = base64ToUint8Array(base64urlUnescape(signature));
                return await window.crypto.subtle.verify({ name: algorithmMap[method].name, hash: algorithmMap[method].hash }, publicKey, signatureArray, data);
            }
            catch (keyError) {
                console.error('Key processing error:', keyError);
                return false;
            }
        }
        return false;
    }
    catch (error) {
        console.error('Verification error:', error);
        return false;
    }
}
async function sign(input, key, method, type) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    if (type === "hmac") {
        const cryptoKey = await window.crypto.subtle.importKey("raw", encoder.encode(key), { name: algorithmMap[method].name, hash: algorithmMap[method].hash }, false, ["sign"]);
        const signature = await window.crypto.subtle.sign(algorithmMap[method], cryptoKey, data);
        return base64urlEscape(uint8ArrayToBase64(new Uint8Array(signature)));
    }
    else if (type === "sign") {
        const privateKey = await window.crypto.subtle.importKey("pkcs8", base64ToUint8Array(key), { name: algorithmMap[method].name, hash: algorithmMap[method].hash }, false, ["sign"]);
        const signature = await window.crypto.subtle.sign(algorithmMap[method], privateKey, data);
        return base64urlEscape(uint8ArrayToBase64(new Uint8Array(signature)));
    }
    throw new Error("Algorithm type not recognized");
}
function base64ToUint8Array(base64) {
    try {
        const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    catch (error) {
        throw new Error('Invalid base64 string');
    }
}
function uint8ArrayToBase64(array) {
    let binary = '';
    const bytes = new Uint8Array(array);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function base64urlDecode(str) {
    try {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(str.length + (4 - str.length % 4) % 4, '=');
        return atob(base64);
    }
    catch (e) {
        throw new Error('Invalid base64 string');
    }
}
function base64urlUnescape(str) {
    return str.replace(/-/g, '+').replace(/_/g, '/').padEnd(str.length + (4 - str.length % 4) % 4, '=');
}
function base64urlEscape(str) {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
const decode = async (token, key, noVerify, algorithm) => {
    // check token
    if (!token) {
        return { type: 'invalid-token', session: undefined };
    }
    const segments = token.split(".");
    if (segments.length !== 3) {
        return { type: 'invalid-token', session: undefined };
    }
    const [headerSeg, payloadSeg, signatureSeg] = segments;
    try {
        const header = JSON.parse(base64urlDecode(headerSeg));
        const payload = JSON.parse(base64urlDecode(payloadSeg));
        if (!noVerify) {
            if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
                algorithm = "RS256";
            }
            const signingMethod = (algorithm || header.alg);
            if (!(signingMethod in algorithmMap)) {
                return { type: 'invalid-token' };
            }
            const signingType = typeMap[signingMethod];
            if (!algorithmMap[signingMethod] || !signingType) {
                return { type: 'invalid-token' };
            }
            const signingInput = [headerSeg, payloadSeg].join(".");
            const isValid = await verify(signingInput, key, signingMethod, signingType, signatureSeg);
            if (!isValid) {
                return { type: 'integrity-error' };
            }
            if (payload.exp && Date.now() > payload.exp * 1000) {
                return { type: 'expired' };
            }
            if (payload.nbf && Date.now() < payload.nbf * 1000) {
                return { type: 'invalid-token' };
            }
        }
        return { type: 'valid', session: payload };
    }
    catch (error) {
        console.error('Decode error:', error);
        return { type: 'invalid-token' };
    }
};
const jwt = {
    decode,
    version: "0.5.6",
};
export default jwt;
export { decode, sign };
