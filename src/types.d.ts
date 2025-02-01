namespace JWT {
  export interface User {
    id: number;
    dateCreated: number;
    username: string;
    password: string;
  }

  export interface Session {
    id: number;
    dateCreated: number;
    username: string;
    role?: string;
    /**
     * Timestamp indicating when the session was created, in Unix milliseconds.
     */
    orig_at: number;
    /**
     * Timestamp indicating when the session should expire, in Unix milliseconds.
     */
    exp: number;
  }
}
/**
 * Identical to the Session type, but without the `issued` and `expires` properties.
 */
export type PartialSession = Omit<JWT.Session, 'orig_at' | 'exp'>;

export interface EncodeResult {
  token: string;
  expires: number;
  issued: number;
}

export type DecodeResult =
  | {
      type: 'valid';
      session: JWT.Session;
    }
  | {
      type: 'integrity-error';
    }
  | {
      type: 'invalid-token';
    }
  | {
      type: 'expired';
    };

export type ExpirationStatus = 'expired' | 'active' | 'grace';
