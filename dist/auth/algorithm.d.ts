import type { DecodeResult } from "../types";
import { algorithmMap } from "../index";
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
declare const decode: (token: string, key: string, noVerify: boolean, algorithm?: keyof typeof algorithmMap) => DecodeResult;
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
declare const encode: (payload: Record<string, any>, key: string, algorithm: keyof typeof algorithmMap, options?: Record<string, any>) => string;
declare const jwt: {
    encode: (payload: Record<string, any>, key: string, algorithm: keyof typeof algorithmMap, options?: Record<string, any>) => string;
    decode: (token: string, key: string, noVerify: boolean, algorithm?: keyof typeof algorithmMap) => DecodeResult;
    version: string;
};
export default jwt;
export { encode, decode };
