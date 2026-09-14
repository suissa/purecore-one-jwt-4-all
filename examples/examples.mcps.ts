import * as crypto from 'node:crypto';
import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';

const { privateKey: AUTH_SERVER_PRIVATE_KEY, publicKey: API_PUBLIC_KEY } = generateKeyPair();

const ISSUER = 'https://meu-auth-server.com';

const AUDIENCE_FINANCEIRO = 'https://api.financeira.com';
const MCP_ECOSYSTEM_AUD = 'urn:mcp:ecosystem';

const MCP_SERVER_ALPHA = 'https://mcp-alpha.internal';
const MCP_SERVER_BETA  = 'https://mcp-beta.internal';
const MCP_SERVER_GAMA  = 'https://mcp-gama.internal';
const MCP_SERVER_DELTA = 'https://mcp-delta.internal';

async function generateAccessToken(userId: string, scopes: string[], audience: string | string[]) {
  const jwt = await new SignJWT({
    sub: userId,
    scope: scopes.join(' '),
    role: 'user'
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setExpirationTime('1h')
    .setJti(crypto.randomUUID())
    .sign(AUTH_SERVER_PRIVATE_KEY);

  return jwt;
}

async function protectMCPServer(serverName: string, myAudienceId: string, tokenRecebido: string) {
  try {
    const { payload } = await jwtVerify(tokenRecebido, API_PUBLIC_KEY, {
      issuer: ISSUER,
      audience: myAudienceId 
    });

    console.log(`✅ [${serverName}] Acesso permitido! (Token aud: ${JSON.stringify(payload.aud)})`);
    return true;

  } catch (error) {
    console.error(`❌ [${serverName}] Acesso negado: ${(error as Error).message}`);
    return false;
  }
}

(async () => {
  console.log("--- Cenário A: Token para um Ecossistema Inteiro ---\n");
  
  const tokenEcosystem = await generateAccessToken('user-A', ['mcp:read'], MCP_ECOSYSTEM_AUD);
  await protectMCPServer('MCP Alpha (Modo Ecossistema)', MCP_ECOSYSTEM_AUD, tokenEcosystem);

  console.log("\n--- Cenário B: Token Restrito a um Grupo Específico (3 Servers) ---\n");
  
  const targetGroup = [MCP_SERVER_ALPHA, MCP_SERVER_BETA, MCP_SERVER_GAMA];
  const tokenGroup = await generateAccessToken('user-B', ['mcp:write'], targetGroup);
  
  await protectMCPServer('MCP Alpha', MCP_SERVER_ALPHA, tokenGroup);
  await protectMCPServer('MCP Gama', MCP_SERVER_GAMA, tokenGroup);
  await protectMCPServer('MCP Delta', MCP_SERVER_DELTA, tokenGroup);

})();
