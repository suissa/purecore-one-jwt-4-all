import { describe, test, expect } from 'bun:test';
import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';

describe('@purecore/one-jwt-4-all', () => {
  const { privateKey, publicKey } = generateKeyPair();

  test('should generate valid keypair', () => {
    expect(privateKey).toContain('BEGIN PRIVATE KEY');
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
  });

  test('should sign and verify a valid JWT', async () => {
    const jwt = await new SignJWT({ userId: 123, role: 'admin' })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer('https://auth.example.com')
      .setAudience('https://api.example.com')
      .setExpirationTime('1h')
      .setSubject('user-123')
      .setJti('unique-token-id-123')
      .sign(privateKey);

    expect(typeof jwt).toBe('string');
    expect(jwt.split('.')).toHaveLength(3);

    const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
      issuer: 'https://auth.example.com',
      audience: 'https://api.example.com',
    });

    expect(protectedHeader.alg).toBe('EdDSA');
    expect(payload.userId).toBe(123);
    expect(payload.role).toBe('admin');
    expect(payload.sub).toBe('user-123');
    expect(payload.iss).toBe('https://auth.example.com');
    expect(payload.jti).toBe('unique-token-id-123');
  });

  test('should reject non-EdDSA algorithm', async () => {
    const signer = new SignJWT({ sub: '123' }).setProtectedHeader({ alg: 'HS256' });
    expect(signer.sign(privateKey)).rejects.toThrow(
      'Apenas o algoritmo EdDSA é suportado por esta implementação.'
    );
  });

  test('should reject malformed JWT format', async () => {
    expect(jwtVerify('invalid.jwt', publicKey)).rejects.toThrow(
      'JWT inválido: Formato deve ser header.payload.signature'
    );
  });

  test('should reject invalid signature', async () => {
    const { publicKey: otherPublicKey } = generateKeyPair();
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .sign(privateKey);

    expect(jwtVerify(jwt, otherPublicKey)).rejects.toThrow('Assinatura do JWT inválida.');
  });

  test('should reject expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setExpirationTime(now - 100)
      .sign(privateKey);

    expect(jwtVerify(jwt, publicKey)).rejects.toThrow('Token expirado (exp).');
  });

  test('should reject token not active yet (nbf)', async () => {
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setNotBefore('1h')
      .sign(privateKey);

    expect(jwtVerify(jwt, publicKey)).rejects.toThrow('Token ainda não ativo (nbf).');
  });

  test('should reject issuer mismatch', async () => {
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer('https://wrong-issuer.com')
      .sign(privateKey);

    expect(
      jwtVerify(jwt, publicKey, { issuer: 'https://expected-issuer.com' })
    ).rejects.toThrow('Issuer inválido.');
  });

  test('should reject audience mismatch', async () => {
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setAudience('https://api-a.com')
      .sign(privateKey);

    expect(
      jwtVerify(jwt, publicKey, { audience: 'https://api-b.com' })
    ).rejects.toThrow('Audience inválida.');
  });

  test('should support multiple audiences in array', async () => {
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setAudience(['https://api-a.com', 'https://api-b.com'])
      .sign(privateKey);

    const { payload } = await jwtVerify(jwt, publicKey, { audience: 'https://api-b.com' });
    expect(payload.sub).toBe('123');
  });

  test('should validate maxTokenAge option', async () => {
    const oldTimestamp = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt(oldTimestamp)
      .sign(privateKey);

    expect(
      jwtVerify(jwt, publicKey, { maxTokenAge: '1h' })
    ).rejects.toThrow('Token excedeu a idade máxima permitida de 1h.');
  });

  test('should verify with currentDate mock option', async () => {
    const futureDate = new Date(Date.now() + 86400000); // Tomorrow
    const jwt = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setExpirationTime('2h')
      .sign(privateKey);

    // Verifying with currentDate set to tomorrow should fail due to expiration
    expect(
      jwtVerify(jwt, publicKey, { currentDate: futureDate })
    ).rejects.toThrow('Token expirado (exp).');
  });
});
