/**
 * module dependencies
 */
import * as crypto from "crypto";
import type { DecodeResult } from "../types";
import  { algorithmMap, typeMap } from "../index";


/**
 * Decode jwt
 *
 * @param {Object} token
 * @param {String} key
 * @param {Boolean} [noVerify]
 * @param {String} [algorithm]
 * @return {Object} payload
 * @api public
 */
const decode = (
	token: string,
	key: string,
	noVerify: boolean,
	algorithm?: keyof typeof algorithmMap
): DecodeResult => {
	// check token
	if (!token) {
        return {'type': 'invalid-token'}
	}
	// check segments
	const segments = token.split(".");
	if (segments.length !== 3) {
        return {type: 'invalid-token'}
	}

	// All segment should be base64
	const headerSeg = segments[0];
	const payloadSeg = segments[1];
	const signatureSeg = segments[2];

	// base64 decode and parse JSON
	const header = JSON.parse(base64urlDecode(headerSeg));
	const payload = JSON.parse(base64urlDecode(payloadSeg));

	if (!noVerify) {
		if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
			algorithm = "RS256";
		}
        console.log({algorithm},  header.alg)
        const signingMethod = (algorithm || header.alg) as keyof typeof algorithmMap;
        if (!(signingMethod in algorithmMap)) throw new Error("Algorithm not recognized");
        const signingType = typeMap[signingMethod];
        
        if (!algorithmMap[signingMethod] || !signingType) {
            throw new Error("Algorithm not supported");
        }

		// verify signature. `sign` will return base64 string.
		const signingInput = [headerSeg, payloadSeg].join(".");
		if (!verify(signingInput, key, signingMethod, signingType, signatureSeg)) {
            return {type: 'integrity-error'};
		}

		// Support for nbf and exp claims.
		// According to the RFC, they should be in seconds.
		if (payload.nbf && Date.now() < payload.nbf * 1000) {
            return {type: 'invalid-token'};
		}

		if (payload.exp && Date.now() > payload.exp * 1000) {
            return {type: 'invalid-token'};
		}
	}

	return {
        type: 'valid',
        session: payload
    };
};

/**
 * Encode jwt
 *
 * @param {Object} payload
 * @param {String} key
 * @param {String} algorithm
 * @param {Object} options
 * @return {String} token
 * @api public
 */
const encode = (
	payload: Record<string, any>,
	key: string,
	algorithm: keyof typeof algorithmMap,
	options?: Record<string, any>
): string => {
	// Check key
	if (!key) {
		throw new Error("Require key");
	}

	// Check algorithm, default is HS256
	if (!algorithm) {
		algorithm = "HS256";
	}

	const signingMethod = algorithmMap[algorithm];
	const signingType = typeMap[algorithm];
	if (!signingMethod || !signingType) {
		throw new Error("Algorithm not supported");
	}

	// header, typ is fixed value.
	const header = { typ: "JWT", alg: algorithm };
	if (options && options.header) {
		assignProperties(header, options.header);
	}

	// create segments, all segments should be base64 string
	const segments = [];
	segments.push(base64urlEncode(JSON.stringify(header)));
	segments.push(base64urlEncode(JSON.stringify(payload)));
	segments.push(sign(segments.join("."), key, algorithm, signingType));

	return segments.join(".");
};

/**
 * private util functions
 */

function assignProperties(dest: Record<string, any>, source: Record<string, any>): void {
	for (const attr in source) {
		if (attr in source) {
			dest[attr] = source[attr];
		}
	}
}

function verifyRsaPublicKey(key: string) {
    try {
        crypto.createPublicKey(key);
        return true;
    } catch (error) {
        return false;
    }
}

function verifyRsaPrivateKey(key: string) {
    try {
        crypto.createPrivateKey(key);
        return true;
    } catch (error) {
        return false;
    }
}

function verify(input: string, key: string, method: keyof typeof algorithmMap, type: typeof typeMap[keyof typeof typeMap], signature: string): boolean {
    if (type === "hmac") {
        return signature === sign(input, key, method, type);
    } else if (type === "sign") {
		if (!verifyRsaPublicKey(key) && !verifyRsaPrivateKey(key)) {
            throw new Error("Invalid RSA key format");
        }
        try {
            // Ensure proper key formatting by replacing raw \n with actual newlines
            const formattedKey = key.replace(/\\n/g, '\n');
            const verifier = crypto.createVerify(algorithmMap[method].hash);
            verifier.update(input);
            return verifier.verify(formattedKey, base64urlUnescape(signature), "base64");
        } catch (error) {
            return false;
        }
    } else {
        throw new Error("Algorithm type not recognized");
    }
}

function sign(input: string, key: string, method: keyof typeof algorithmMap, type: typeof typeMap[keyof typeof typeMap]): string {
    let base64str;
    if (type === "hmac") {
        base64str = crypto.createHmac(algorithmMap[method].hash, key).update(input).digest("base64");
    } else if (type === "sign") {
        if (!verifyRsaPublicKey(key) &&!verifyRsaPrivateKey(key)) {
            throw new Error("Invalid RSA key format");
        }
        // Ensure proper key formatting by replacing raw \n with actual newlines
        const formattedKey = key.replace(/\\n/g, '\n');
        const signer = crypto.createSign(algorithmMap[method].hash);
        signer.update(input);
        base64str = signer.sign(formattedKey, "base64");
    } else {
        throw new Error("Algorithm type not recognized");
    }

    return base64urlEscape(base64str);
}

function base64urlDecode(str: string): string {
    try {
        const base64 = base64urlUnescape(str);
        return Buffer.from(base64, 'base64').toString();
    } catch (e) {
        throw new Error('Invalid base64 string');
    }
}

function base64urlUnescape(str: string): string {
    let output = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += '==';
            break;
        case 3:
            output += '=';
            break;
        default:
            throw new Error('Illegal base64url string!');
    }
    return output;
}

function base64urlEncode(str: string): string {
	return base64urlEscape(Buffer.from(str).toString("base64"));
}

function base64urlEscape(str: string): string {
	return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

const jwt = {
	encode,
	decode,
	version: "0.5.6",
};

export default jwt;
export { encode, decode };
