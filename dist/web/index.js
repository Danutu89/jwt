import { decode } from "./algorithm.js";
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
