import { encode } from "../auth/algorithm";
import { decode } from "./algorithm";
export function encodeSession(secretKey, partialSession, algorithm) {
    const issued = Date.now();
    const fifteenMinutesInMs = 15 * 60 * 1000;
    const expires = issued + fifteenMinutesInMs;
    const session = {
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
export async function decodeSession(secretKey, tokenString, noVerify = false, algorithm) {
    return await decode(tokenString, secretKey, noVerify, algorithm);
}
export function checkExpirationStatus(token) {
    const now = new Date().getTime() / 1000;
    if (token.exp > now)
        return 'active';
    const threeHoursInMs = 3 * 60 * 60 * 1000;
    const threeHoursAfterExpiration = token.exp + threeHoursInMs;
    if (threeHoursAfterExpiration > now)
        return 'grace';
    return 'expired';
}
