import * as web from './web/index';
import * as node from './auth/index';
import type { PartialSession } from './types'

export const algorithmMap = {
  HS256: { name: 'HMAC', hash: 'SHA-256' },
  HS384: { name: 'HMAC', hash: 'SHA-384' },
  HS512: { name: 'HMAC', hash: 'SHA-512' },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  'RSA-SHA256': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  SHA256: { name: 'HMAC', hash: 'SHA-256' },
  SHA384: { name: 'HMAC', hash: 'SHA-384' },
  SHA512: { name: 'HMAC', hash: 'SHA-512' },
};

export const typeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign',
  'RSA-SHA256': 'sign',
  SHA256: 'hmac',
  SHA384: 'hmac',
  SHA512: 'hmac',
};

export function decodeSession(
  secretKey: string,
  tokenString: string,
  noVerify = false,
  algorithm?: keyof typeof algorithmMap
) {
  if (typeof window === 'undefined')
    return node.decodeSession(secretKey, tokenString, noVerify, algorithm);
  return web.decodeSession(secretKey, tokenString, noVerify, algorithm);
}

export function encodeSession(
  secretKey: string,
  partialSession: PartialSession,
  algorithm: keyof typeof algorithmMap
) {
  if (typeof window === 'undefined')
    return node.encodeSession(secretKey, partialSession, algorithm);
  return web.encodeSession(secretKey, partialSession, algorithm);
}
