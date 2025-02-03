import type { JWT, ExpirationStatus } from "../types.js";
import { algorithmMap } from "../index.js";
export declare function decodeSession(secretKey: string, tokenString: string, noVerify?: boolean, algorithm?: keyof typeof algorithmMap): Promise<import("../types.js").DecodeResult>;
export declare function checkExpirationStatus(token: JWT.Session): ExpirationStatus;
