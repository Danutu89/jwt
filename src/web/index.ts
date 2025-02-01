import { encode } from "../auth/algorithm";
import type {
	JWT,
	ExpirationStatus,
	PartialSession,
	EncodeResult,
} from "../types";
import { decode } from "./algorithm";
import  { algorithmMap } from "../index";

export function encodeSession(secretKey: string, partialSession: PartialSession, algorithm:  keyof typeof algorithmMap): EncodeResult {
    const issued = Date.now();
    const fifteenMinutesInMs = 15 * 60 * 1000;
    const expires = issued + fifteenMinutesInMs;
    const session: JWT.Session = {
        ...partialSession,
        orig_at: issued,
        exp: expires
    };

    return {
        token: encode(session, secretKey, algorithm),
        issued: issued,
        expires: expires
    };
}

export async function decodeSession(secretKey: string, tokenString: string, noVerify = false, algorithm?:  keyof typeof algorithmMap) {
    return await decode(tokenString, secretKey, noVerify, algorithm);
    
}

export function checkExpirationStatus(token: JWT.Session): ExpirationStatus {
    const now = new Date().getTime() / 1000;

    if (token.exp > now) return 'active';

    const threeHoursInMs = 3 * 60 * 60 * 1000;
    const threeHoursAfterExpiration = token.exp + threeHoursInMs;

    if (threeHoursAfterExpiration > now) return 'grace';

    return 'expired';
}