import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';

const { privateKey: AUTH_SERVER_PRIVATE_KEY, publicKey: API_PUBLIC_KEY } = generateKeyPair();

const ISSUER = 'https://meu-auth-server.com';
const AUDIENCE_FINANCEIRO = 'https://api.financeira.com';

async function generateAccessToken(userId: string, scopes: string[]) {
  const jwt = await new SignJWT({
    sub: userId,
    scope: scopes.join(' '),
    role: 'admin' 
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE_FINANCEIRO)
    .setExpirationTime('1h')
    .setJti(crypto.randomUUID())
    .sign(AUTH_SERVER_PRIVATE_KEY);

  return jwt;
}

async function protectFinanceRoute(tokenRecebido: string) {
  try {
    const { payload } = await jwtVerify(tokenRecebido, API_PUBLIC_KEY, {
      issuer: ISSUER,
      audience: AUDIENCE_FINANCEIRO
    });

    console.log(`✅ Acesso permitido ao usuário ${payload.sub}`);
    console.log(`Escopos permitidos: ${payload.scope}`);
    
    return true;

  } catch (error) {
    console.error(`❌ Acesso negado: ${(error as Error).message}`);
    return false;
  }
}

(async () => {
  console.log("--- Iniciando Fluxo OAuth 2.1 com EdDSA ---\n");

  console.log("1. Gerando Access Token no Auth Server...");
  const token = await generateAccessToken('user-123', ['read:invoices', 'write:payments']);
  console.log("Token gerado:\n", token);

  console.log("\n2. Tentando acessar API Financeira...");
  await protectFinanceRoute(token);

  console.log("\n3. Teste de Segurança (Audiência Errada)...");
  try {
    await jwtVerify(token, API_PUBLIC_KEY, {
      issuer: ISSUER,
      audience: 'https://api.chat.com'
    });
  } catch (e) {
    console.log(`Bloqueio esperado: ${(e as Error).message}`);
  }
})();
