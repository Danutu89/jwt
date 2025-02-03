import type {
	JWT,
	ExpirationStatus,
} from "../types.js";
import { decode } from "./algorithm.js";
import  { algorithmMap } from "../index.js";


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