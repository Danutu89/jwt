import type { JWT, ExpirationStatus, PartialSession, EncodeResult } from "../types";
import { algorithmMap } from "../index";
export declare function encodeSession(secretKey: string, partialSession: PartialSession, algorithm: keyof typeof algorithmMap): EncodeResult;
export declare function decodeSession(secretKey: string, tokenString: string, noVerify?: boolean, algorithm?: keyof typeof algorithmMap): Promise<import("../types").DecodeResult>;
export declare function checkExpirationStatus(token: JWT.Session): ExpirationStatus;
