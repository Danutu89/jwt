/**
 * module dependencies
 */
import type { DecodeResult } from "../types.js";
import { algorithmMap } from "../index.js";
declare function sign(input: string, key: string, method: keyof typeof algorithmMap, type: string): Promise<string>;
declare const decode: (token: string, key: string, noVerify: boolean, algorithm?: keyof typeof algorithmMap) => Promise<DecodeResult>;
declare const jwt: {
    decode: (token: string, key: string, noVerify: boolean, algorithm?: keyof typeof algorithmMap) => Promise<DecodeResult>;
    version: string;
};
export default jwt;
export { decode, sign };
