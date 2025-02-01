import type { PartialSession } from './types';
export declare const algorithmMap: {
    HS256: {
        name: string;
        hash: string;
    };
    HS384: {
        name: string;
        hash: string;
    };
    HS512: {
        name: string;
        hash: string;
    };
    RS256: {
        name: string;
        hash: string;
    };
    'RSA-SHA256': {
        name: string;
        hash: string;
    };
    SHA256: {
        name: string;
        hash: string;
    };
    SHA384: {
        name: string;
        hash: string;
    };
    SHA512: {
        name: string;
        hash: string;
    };
};
export declare const typeMap: {
    HS256: string;
    HS384: string;
    HS512: string;
    RS256: string;
    'RSA-SHA256': string;
    SHA256: string;
    SHA384: string;
    SHA512: string;
};
export declare function decodeSession(secretKey: string, tokenString: string, noVerify?: boolean, algorithm?: keyof typeof algorithmMap): import("./types").DecodeResult | Promise<import("./types").DecodeResult>;
export declare function encodeSession(secretKey: string, partialSession: PartialSession, algorithm: keyof typeof algorithmMap): import("./types").EncodeResult;
