# JWT

A lightweight and secure JSON Web Token (JWT) implementation for TypeScript/JavaScript applications.

## Installation

```bash
npm install jwt
# or
yarn add jwt
# or
pnpm add jwt
```

## Supported Algorithms

This library supports the following algorithms:

### HMAC-based Algorithms

- **HS256 (HMAC with SHA-256)**: The most commonly used algorithm, providing a good balance between security and performance. Recommended for most applications.
- **HS384 (HMAC with SHA-384)**: Offers increased security over HS256 with slightly lower performance. Suitable for applications requiring higher security levels.
- **HS512 (HMAC with SHA-512)**: Provides the highest security level among the supported HMAC algorithms. Best for applications with strict security requirements.

### RSA-based Algorithms

- **RS256 (RSA with SHA-256)**: RSA-based signing with 2048-bit key length, suitable for most applications requiring asymmetric cryptography.
- **RS384 (RSA with SHA-384)**: Increased security with 3072-bit key length, recommended for higher security requirements.
- **RS512 (RSA with SHA-512)**: Maximum security with 4096-bit key length, ideal for highly sensitive applications.

#### Key Generation for RSA

For RSA-based algorithms, you'll need to generate a public/private key pair. Here's how to generate them using OpenSSL:

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key from private key
openssl rsa -in private.pem -pubout -out public.pem
```

## Usage

### Environment-Specific Imports

The package provides different entry points for browser and Node.js environments:

```typescript
// For browser environments
import { encodeSession, decodeSession, checkExpirationStatus } from 'jwt/web';

// For Node.js environments
import { encodeSession, decodeSession, checkExpirationStatus } from 'jwt/auth';
```

### Basic Example

```typescript
import { encodeSession, decodeSession, checkExpirationStatus } from 'jwt';

// Create a new session token
const partialSession = {
    id: "user123",
    username: "john.doe",
    role: "admin"
};

// For HMAC-based algorithms
const secretKey = "your-secret-key";
const algorithm = "HS256"; // Supported HMAC algorithms: HS256, HS384, HS512

// For RSA-based algorithms
const privateKey = fs.readFileSync('private.pem');
const publicKey = fs.readFileSync('public.pem');
const rsaAlgorithm = "RS256"; // Supported RSA algorithms: RS256, RS384, RS512

// Encode session
const { token, issued, expires } = encodeSession(secretKey, partialSession, algorithm);

// Decode session
const decodedResult = decodeSession(secretKey, token, false, algorithm);

// Check token expiration status
if (decodedResult.type === 'valid') {
    const expirationStatus = checkExpirationStatus(decodedResult.session);
    console.log('Token status:', expirationStatus); // 'active', 'grace', or 'expired'
}
```

### Custom Session Types

You can extend the default Session interface by declaring your own interface in the JWT namespace:

```typescript
declare namespace JWT {
    interface Session {
        id: string;
        username: string;
        role: string;
        // Add your custom properties here
        permissions?: string[];
        organization?: string;
        // ... any other custom fields
    }
}
```

## API Reference

### encodeSession(secretKey, partialSession, algorithm)

Creates a new JWT session token.

- `secretKey`: String - The secret key used for signing the token
- `partialSession`: Object - The session data to encode
- `algorithm`: String - The signing algorithm to use (HS256, HS384, HS512)

Returns an object containing:
- `token`: The JWT string
- `issued`: Timestamp when the token was issued
- `expires`: Timestamp when the token will expire

### decodeSession(secretKey, tokenString, noVerify, algorithm)

Decodes and verifies a JWT token.

- `secretKey`: String - The secret key used for verification
- `tokenString`: String - The JWT token to decode
- `noVerify`: Boolean - Skip signature verification if true
- `algorithm`: String - The algorithm used for verification

Returns a DecodeResult object with either:
- Valid token: `{ type: 'valid', session: Session }`
- Invalid token: `{ type: 'invalid', error: string }`

### checkExpirationStatus(token)

Checks the expiration status of a decoded token.

- `token`: Session - The decoded token session

Returns one of:
- `'active'`: Token is still valid
- `'grace'`: Token is expired but within grace period (3 hours)
- `'expired'`: Token is expired and beyond grace period

## License

MIT

## Author

Danutu89