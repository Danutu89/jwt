import { describe, it, expect } from 'vitest';
import { encodeSession, decodeSession } from '../src/auth';
import {
  decodeSession as webDecodeSession,
  encodeSession as webEncodeSession,
} from '../src/web';
import * as crypto from 'crypto';

describe('JWT Node Environment', () => {
  const secretKey = 'test-secret-key';
  const mockSession = {
    id: 123,
    username: 'test-user',
    dateCreated: Date.now(),
    role: 'admin',
  };

  describe('HS256 Algorithm', () => {
    it('should encode and decode a valid session', () => {
      const encoded = encodeSession(secretKey, mockSession, 'HS256');
      expect(encoded).toHaveProperty('token');
      expect(encoded).toHaveProperty('issued');
      expect(encoded).toHaveProperty('expires');

      const decoded = decodeSession(secretKey, encoded.token);
      expect(decoded.type).toBe('valid');
      if (decoded.type === 'valid') {
        expect(decoded.session.id).toBe(mockSession.id);
        expect(decoded.session.username).toBe(mockSession.username);
        expect(decoded.session.dateCreated).toBe(mockSession.dateCreated);
      }
    });

    it('should handle invalid tokens', () => {
      const result = decodeSession(secretKey, 'invalid-token');
      expect(result.type).toBe('invalid-token');
    });

    it('should handle tampered tokens', () => {
      const encoded = encodeSession(secretKey, mockSession, 'HS256');
      const tamperedToken = encoded.token.slice(0, -5) + 'xxxxx';
      const result = decodeSession(secretKey, tamperedToken);
      expect(result.type).toBe('integrity-error');
    });
  });

  describe('RSA Key Pair', () => {
    let privateKey: string;
    let publicKey: string;

      // Generate a new RSA key pair before each test
      const {
        privateKey: privKey,
        publicKey: pubKey,
      } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });
      privateKey = privKey;
      publicKey = pubKey;

    it('should encode with private key and decode with public key', () => {
      const encoded = encodeSession(privateKey, mockSession, 'RS256');
      expect(encoded).toHaveProperty('token');
      expect(encoded).toHaveProperty('issued');
      expect(encoded).toHaveProperty('expires');

      const decoded = decodeSession(publicKey, encoded.token);
      expect(decoded.type).toBe('valid');
      if (decoded.type === 'valid') {
        expect(decoded.session.id).toBe(mockSession.id);
        expect(decoded.session.username).toBe(mockSession.username);
        expect(decoded.session.role).toBe(mockSession.role);
      }
    });

    it('should fail when using wrong public key', () => {
      const encoded = encodeSession(privateKey, mockSession, 'RS256');
      // Generate a different key pair to test with wrong public key
      const { publicKey: wrongPublicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });
      const result = decodeSession(wrongPublicKey, encoded.token);
      expect(result.type).toBe('integrity-error');
    });
  });
});

describe('JWT Web Environment', () => {
  const secretKey = 'test-secret-key';
  const mockSession = {
    id: 123,
    username: 'test-user',
    dateCreated: Date.now(),
    role: 'admin',
  };

  describe('HS256 Algorithm', () => {
    it('should decode a valid token', async () => {
      const validToken = webEncodeSession(secretKey, mockSession, 'HS256')
        .token;

      const result = await webDecodeSession(
        secretKey,
        validToken,
        false,
        'HS256'
      );
      expect(result.type).toBe('valid');
      if (result.type === 'valid') {
        expect(result.session.id).toBe(123);
        expect(result.session.username).toBe('test-user');
        expect(result.session.role).toBe('admin');
      }
    });

    it('should handle invalid tokens', async () => {
      const result = await webDecodeSession(
        secretKey,
        'invalid-token',
        false,
        'HS256'
      );
      expect(result.type).toBe('invalid-token');
    });

    it('should handle tampered tokens', async () => {
      const validToken = webEncodeSession(secretKey, mockSession, 'HS256')
        .token;

      const tamperedToken = validToken.slice(0, -5) + 'xxxxx';
      const result = await webDecodeSession(
        secretKey,
        tamperedToken,
        false,
        'HS256'
      );
      expect(result.type).toBe('integrity-error');
    });
  });

  describe('SHA256 Algorithm', () => {
    it('should decode with SHA256', async () => {
      const validToken = webEncodeSession(secretKey, mockSession, 'SHA256')
        .token;

      const result = await webDecodeSession(
        secretKey,
        validToken,
        false,
        'SHA256'
      );
      expect(result.type).toBe('valid');
    });
  });

  describe('SHA384 Algorithm', () => {
    it('should decode with SHA384', async () => {
      const validToken = webEncodeSession(secretKey, mockSession, 'SHA384')
        .token;

      const result = await webDecodeSession(
        secretKey,
        validToken,
        false,
        'SHA384'
      );
      expect(result.type).toBe('valid');
    });
  });

  describe('SHA512 Algorithm', () => {
    it('should decode with SHA512', async () => {
      const validToken = webEncodeSession(secretKey, mockSession, 'SHA512')
        .token;

      const result = await webDecodeSession(
        secretKey,
        validToken,
        false,
        'SHA512'
      );
      expect(result.type).toBe('valid');
    });
  });

  describe('RSA Key Pair', () => {
    let publicKey: string = '';
    let privateKey: string = '';

      // Generate a new RSA key pair before each test
      const {
        publicKey: pubKey,
        privateKey: privKey,
      } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });
      publicKey = pubKey;
      privateKey = privKey;

    const rsaToken = webEncodeSession(
      privateKey,
      {
        id: 123,
        username: 'test-user',
        role: 'admin',
        dateCreated: new Date().getTime(),
      },
      'RS256'
    ).token;

    it('should decode a valid RSA token', async () => {
      const result = await webDecodeSession(
        rsaToken,
        publicKey,
        false,
        'RS256'
      );
      expect(result.type).toBe('valid');
      if (result.type === 'valid') {
        expect(result.session.id).toBe(123);
        expect(result.session.username).toBe('test-user');
        expect(result.session.role).toBe('admin');
      }
    });

    it('should handle invalid RSA public key', async () => {
      const wrongPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqEFLlbzRErDlrZ6TnNq
JZJXHYn1s0s0Q9CA+XnJQ1QQvqS6m1yh0AG0jv4YPyqr2zVjbm7ayKBHkwqhPxhB
QHVS8D9ZF9cLOhF/ndX8aNX4THVhyFh+91Y9JpXXlKwCQ5n0S6nH1pSH4qBBgfyH
JZTKqB6kE/K+nhzR5OaVtKnH1vR6b9TtYlZdY7P6Rt3jUuMYzh4jC4BTwVN6Af6p
Y6sBR6qvV9frbWBP9Q==
-----END PUBLIC KEY-----`;
      const result = await webDecodeSession(
        rsaToken,
        wrongPublicKey,
        false,
        'RS256'
      );
      expect(result.type).toBe('integrity-error');
    });

    it('should handle tampered RSA tokens', async () => {
      const tamperedToken = rsaToken.slice(0, -5) + 'xxxxx';
      const result = await webDecodeSession(
        tamperedToken,
        publicKey,
        false,
        'RS256'
      );
      expect(result.type).toBe('integrity-error');
    });

    it('should handle expired RSA tokens', async () => {
      const expiredToken = 
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyIsInVzZXJuYW1lIjoidGVzdC11c2VyIiwicm9sZSI6ImFkbWluIiwib3JpZ19hdCI6MTYzMDAwMDAwMDAwMCwiZXhwIjoxNjMwMDAwMDAwMDAwfQ.RjGjF8BJBwYBvwWXLHqMwLhz1q6S3kR3JQ6g9z8XyQz2M8k9XyQ6q5j2yQ5f3tK8ZyQ6q5j2yQ5f3tK8';
      const result = await webDecodeSession(
        expiredToken,
        publicKey,
        true,
        'RS256'
      );
      expect(result.type).toBe('expired');
    });
  });
});