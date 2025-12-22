/**
 * Signal Protocol End-to-End Encryption para Sistema de Agentes
 * 
 * Implementação do Double Ratchet Algorithm do Signal Protocol para
 * comunicação end-to-end encriptada entre agentes.
 * 
 * Características:
 * - X3DH (Extended Triple Diffie-Hellman) para key agreement inicial
 * - Double Ratchet para forward secrecy e break-in recovery
 * - Cada mensagem usa uma chave única derivada
 * - Perfect Forward Secrecy (PFS)
 * - Post-Compromise Security (PCS)
 * 
 * @see https://signal.org/docs/specifications/doubleratchet/
 * @see https://signal.org/docs/specifications/x3dh/
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

// ============================================================================
// Constantes e Tipos
// ============================================================================

const SYMMETRIC_KEY_LENGTH = 32; // 256 bits
const MAX_SKIP = 1000; // Máximo de message keys puladas para guardar

interface KeyBundle {
  identityKey: Buffer;       // Chave de identidade de longo prazo (pública)
  signedPreKey: Buffer;      // Pre-key assinada (pública)
  signedPreKeySignature: Buffer;
  oneTimePreKey?: Buffer;    // Pre-key única (pública, opcional)
  ephemeralKey?: Buffer;     // Chave efêmera do remetente
}

interface X3DHKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

interface RatchetState {
  DHs: X3DHKeyPair;              // Ratchet key pair próprio
  DHr: Buffer | null;            // Ratchet public key do peer
  RK: Buffer;                    // Root key
  CKs: Buffer | null;            // Sending chain key
  CKr: Buffer | null;            // Receiving chain key
  Ns: number;                    // Número de mensagens enviadas na chain atual
  Nr: number;                    // Número de mensagens recebidas na chain atual
  PN: number;                    // Número de mensagens da chain anterior
  MKSKIPPED: Map<string, Buffer>; // Skipped message keys
}

interface SignalMessage {
  from: string;
  to: string;
  messageId: string;
  timestamp: number;
  header: {
    dh: string;        // Ratchet public key (hex)
    pn: number;        // Previous chain length
    n: number;         // Message number
  };
  ciphertext: string;  // Encrypted content (hex)
  nonce: string;       // Nonce usado (hex)
  jwt?: string;        // JWT opcional para contexto
}

// ============================================================================
// Funções Criptográficas
// ============================================================================

/**
 * Gera par de chaves X25519 para Diffie-Hellman
 */
function generateX25519KeyPair(): X3DHKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    publicKey: Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).slice(-32)),
    privateKey: Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32))
  };
}

/**
 * Computa Diffie-Hellman shared secret
 */
function computeDH(privateKey: Buffer, publicKey: Buffer): Buffer {
  const privKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      privateKey
    ]),
    format: 'der',
    type: 'pkcs8'
  });
  
  const pubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      publicKey
    ]),
    format: 'der',
    type: 'spki'
  });

  return crypto.diffieHellman({
    privateKey: privKeyObj,
    publicKey: pubKeyObj
  });
}

/**
 * HKDF - Hash-based Key Derivation Function
 */
function hkdf(
  inputKeyMaterial: Buffer,
  salt: Buffer,
  info: Buffer,
  length: number
): Buffer {
  return crypto.hkdfSync('sha256', inputKeyMaterial, salt, info, length);
}

/**
 * KDF para Root Chain - deriva novo RK e Chain Key
 */
function kdfRK(rk: Buffer, dhOut: Buffer): { rootKey: Buffer; chainKey: Buffer } {
  const output = hkdf(dhOut, rk, Buffer.from('SignalRootRatchet'), 64);
  return {
    rootKey: output.slice(0, 32),
    chainKey: output.slice(32, 64)
  };
}

/**
 * KDF para Chain Key - deriva novo CK e Message Key
 */
function kdfCK(ck: Buffer): { chainKey: Buffer; messageKey: Buffer } {
  const chainKey = crypto.createHmac('sha256', ck).update(Buffer.from([0x01])).digest();
  const messageKey = crypto.createHmac('sha256', ck).update(Buffer.from([0x02])).digest();
  return { chainKey, messageKey };
}

/**
 * Encripta mensagem usando AES-256-GCM
 */
function encrypt(plaintext: string, key: Buffer): { ciphertext: Buffer; nonce: Buffer } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([encrypted, authTag]),
    nonce
  };
}

/**
 * Decripta mensagem usando AES-256-GCM
 */
function decrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer): string {
  const authTag = ciphertext.slice(-16);
  const encrypted = ciphertext.slice(0, -16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted) + decipher.final('utf8');
}

// ============================================================================
// X3DH Key Agreement Protocol
// ============================================================================

class X3DHKeyBundle {
  readonly identityKey: X3DHKeyPair;
  readonly signedPreKey: X3DHKeyPair;
  readonly signedPreKeySignature: Buffer;
  readonly oneTimePreKeys: X3DHKeyPair[];
  private readonly signingKey: crypto.KeyObject;

  constructor() {
    // Gerar Identity Key (longo prazo)
    this.identityKey = generateX25519KeyPair();
    
    // Gerar Signed Pre-Key
    this.signedPreKey = generateX25519KeyPair();
    
    // Assinar a Pre-Key com Ed25519
    const { publicKey: edPub, privateKey: edPriv } = crypto.generateKeyPairSync('ed25519');
    this.signingKey = edPriv;
    this.signedPreKeySignature = crypto.sign(null, this.signedPreKey.publicKey, edPriv);
    
    // Gerar One-Time Pre-Keys
    this.oneTimePreKeys = Array.from({ length: 10 }, () => generateX25519KeyPair());
  }

  getPublicBundle(): KeyBundle {
    const oneTimePreKey = this.oneTimePreKeys.shift();
    return {
      identityKey: this.identityKey.publicKey,
      signedPreKey: this.signedPreKey.publicKey,
      signedPreKeySignature: this.signedPreKeySignature,
      oneTimePreKey: oneTimePreKey?.publicKey
    };
  }

  /**
   * Executa X3DH como receptor (Bob)
   */
  performX3DHAsReceiver(
    ephemeralKey: Buffer,
    senderIdentityKey: Buffer,
    usedOneTimePreKey: boolean
  ): Buffer {
    // DH1: IKa, SPKb
    const dh1 = computeDH(this.signedPreKey.privateKey, senderIdentityKey);
    
    // DH2: EKa, IKb
    const dh2 = computeDH(this.identityKey.privateKey, ephemeralKey);
    
    // DH3: EKa, SPKb
    const dh3 = computeDH(this.signedPreKey.privateKey, ephemeralKey);
    
    let masterSecret: Buffer;
    if (usedOneTimePreKey && this.oneTimePreKeys.length > 0) {
      // DH4: EKa, OPKb (se one-time pre-key foi usada)
      const otpk = this.oneTimePreKeys[0];
      const dh4 = computeDH(otpk.privateKey, ephemeralKey);
      masterSecret = Buffer.concat([dh1, dh2, dh3, dh4]);
    } else {
      masterSecret = Buffer.concat([dh1, dh2, dh3]);
    }

    return hkdf(masterSecret, Buffer.alloc(32), Buffer.from('X3DH'), 32);
  }
}

/**
 * Executa X3DH como iniciador (Alice)
 */
function performX3DHAsInitiator(
  identityKey: X3DHKeyPair,
  ephemeralKey: X3DHKeyPair,
  receiverBundle: KeyBundle
): Buffer {
  // DH1: IKa, SPKb
  const dh1 = computeDH(identityKey.privateKey, receiverBundle.signedPreKey);
  
  // DH2: EKa, IKb
  const dh2 = computeDH(ephemeralKey.privateKey, receiverBundle.identityKey);
  
  // DH3: EKa, SPKb
  const dh3 = computeDH(ephemeralKey.privateKey, receiverBundle.signedPreKey);
  
  let masterSecret: Buffer;
  if (receiverBundle.oneTimePreKey) {
    // DH4: EKa, OPKb
    const dh4 = computeDH(ephemeralKey.privateKey, receiverBundle.oneTimePreKey);
    masterSecret = Buffer.concat([dh1, dh2, dh3, dh4]);
  } else {
    masterSecret = Buffer.concat([dh1, dh2, dh3]);
  }

  return hkdf(masterSecret, Buffer.alloc(32), Buffer.from('X3DH'), 32);
}

// ============================================================================
// Double Ratchet State Machine
// ============================================================================

class DoubleRatchet {
  private state: RatchetState;

  constructor() {
    this.state = {
      DHs: generateX25519KeyPair(),
      DHr: null,
      RK: Buffer.alloc(32),
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: new Map()
    };
  }

  /**
   * Inicializa como Alice (iniciadora da sessão)
   */
  initializeAsAlice(sharedSecret: Buffer, bobRatchetPublicKey: Buffer): void {
    this.state.DHs = generateX25519KeyPair();
    this.state.DHr = bobRatchetPublicKey;
    
    // Deriva root key e sending chain key iniciais
    const dhOutput = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey, chainKey } = kdfRK(sharedSecret, dhOutput);
    
    this.state.RK = rootKey;
    this.state.CKs = chainKey;
    this.state.CKr = null;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.PN = 0;
  }

  /**
   * Inicializa como Bob (receptor da sessão)
   */
  initializeAsBob(sharedSecret: Buffer): void {
    this.state.DHs = generateX25519KeyPair();
    this.state.DHr = null;
    this.state.RK = sharedSecret;
    this.state.CKs = null;
    this.state.CKr = null;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.PN = 0;
  }

  /**
   * Encripta uma mensagem
   */
  ratchetEncrypt(plaintext: string): { header: SignalMessage['header']; ciphertext: Buffer; nonce: Buffer } {
    if (!this.state.CKs) {
      throw new Error('Sending chain não inicializada');
    }

    const { chainKey, messageKey } = kdfCK(this.state.CKs);
    this.state.CKs = chainKey;

    const header = {
      dh: this.state.DHs.publicKey.toString('hex'),
      pn: this.state.PN,
      n: this.state.Ns
    };

    this.state.Ns++;

    const { ciphertext, nonce } = encrypt(plaintext, messageKey);

    // Limpa message key da memória
    messageKey.fill(0);

    return { header, ciphertext, nonce };
  }

  /**
   * Decripta uma mensagem
   */
  ratchetDecrypt(header: SignalMessage['header'], ciphertext: Buffer, nonce: Buffer): string {
    const dhPublicKey = Buffer.from(header.dh, 'hex');

    // Tenta chaves puladas primeiro
    const skippedKey = this.trySkippedMessageKeys(header, dhPublicKey);
    if (skippedKey) {
      const plaintext = decrypt(ciphertext, skippedKey, nonce);
      skippedKey.fill(0);
      return plaintext;
    }

    // Verifica se precisamos fazer DH ratchet
    if (!this.state.DHr || !dhPublicKey.equals(this.state.DHr)) {
      this.skipMessageKeys(header.pn);
      this.dhRatchet(dhPublicKey);
    }

    this.skipMessageKeys(header.n);

    if (!this.state.CKr) {
      throw new Error('Receiving chain não inicializada');
    }

    const { chainKey, messageKey } = kdfCK(this.state.CKr);
    this.state.CKr = chainKey;
    this.state.Nr++;

    const plaintext = decrypt(ciphertext, messageKey, nonce);
    messageKey.fill(0);

    return plaintext;
  }

  /**
   * Realiza DH Ratchet step
   */
  private dhRatchet(dhPublicKey: Buffer): void {
    this.state.PN = this.state.Ns;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.DHr = dhPublicKey;

    // Deriva receiving chain
    const dhOutput1 = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey: rk1, chainKey: ckr } = kdfRK(this.state.RK, dhOutput1);
    this.state.RK = rk1;
    this.state.CKr = ckr;

    // Gera novo DH key pair e deriva sending chain
    this.state.DHs = generateX25519KeyPair();
    const dhOutput2 = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey: rk2, chainKey: cks } = kdfRK(this.state.RK, dhOutput2);
    this.state.RK = rk2;
    this.state.CKs = cks;
  }

  /**
   * Armazena message keys puladas
   */
  private skipMessageKeys(until: number): void {
    if (!this.state.CKr) return;

    if (this.state.Nr + MAX_SKIP < until) {
      throw new Error('Muitas mensagens puladas');
    }

    while (this.state.Nr < until) {
      const { chainKey, messageKey } = kdfCK(this.state.CKr);
      this.state.CKr = chainKey;
      
      const key = `${this.state.DHr?.toString('hex')}-${this.state.Nr}`;
      this.state.MKSKIPPED.set(key, messageKey);
      
      this.state.Nr++;
    }
  }

  /**
   * Tenta usar uma message key pulada
   */
  private trySkippedMessageKeys(header: SignalMessage['header'], dhPublicKey: Buffer): Buffer | null {
    const key = `${dhPublicKey.toString('hex')}-${header.n}`;
    const messageKey = this.state.MKSKIPPED.get(key);
    
    if (messageKey) {
      this.state.MKSKIPPED.delete(key);
      return messageKey;
    }
    
    return null;
  }

  /**
   * Retorna public key atual para inicialização do peer
   */
  getPublicKey(): Buffer {
    return this.state.DHs.publicKey;
  }
}

// ============================================================================
// Token Authority (integração com JWT)
// ============================================================================

class TokenAuthority {
  private privateKey: crypto.KeyObject;
  public publicKey: crypto.KeyObject;
  private issuer = 'urn:agentic-system:authority';
  private audience = 'urn:agentic-system:agents';

  constructor() {
    const keys = generateKeyPair();
    this.privateKey = crypto.createPrivateKey(keys.privateKey);
    this.publicKey = crypto.createPublicKey(keys.publicKey);
  }

  async issueAgentToken(
    agentId: string,
    conversationId: string,
    capabilities: string[] = []
  ): Promise<string> {
    return await new SignJWT({
      agentId,
      conversationId,
      capabilities,
      encryptionProtocol: 'signal-e2ee',
      issuedAt: Date.now()
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(agentId)
      .setExpirationTime('5m')
      .sign(this.privateKey);
  }

  async verifyToken(token: string): Promise<any> {
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: this.issuer,
      audience: this.audience
    });
    return payload;
  }
}

// ============================================================================
// Agente com Signal E2EE
// ============================================================================

class SignalE2EEAgent extends EventEmitter {
  readonly agentId: string;
  private keyBundle: X3DHKeyBundle;
  private sessions: Map<string, DoubleRatchet> = new Map();
  private messageHistory: SignalMessage[] = [];
  private token: string | null = null;
  private authority: TokenAuthority;
  private conversationId: string;
  private peerPublicBundles: Map<string, KeyBundle> = new Map();
  private identityKey: X3DHKeyPair;

  constructor(
    agentId: string,
    authority: TokenAuthority,
    capabilities: string[] = []
  ) {
    super();
    this.agentId = agentId;
    this.authority = authority;
    this.keyBundle = new X3DHKeyBundle();
    this.identityKey = generateX25519KeyPair();
    this.conversationId = `conv-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  async initialize(): Promise<void> {
    this.token = await this.authority.issueAgentToken(
      this.agentId,
      this.conversationId
    );
    console.log(`🔐 [${this.agentId}] Agente Signal E2EE inicializado`);
  }

  /**
   * Retorna bundle público para troca de chaves
   */
  getPublicKeyBundle(): KeyBundle {
    return this.keyBundle.getPublicBundle();
  }

  /**
   * Armazena bundle público de um peer
   */
  registerPeerBundle(peerId: string, bundle: KeyBundle): void {
    this.peerPublicBundles.set(peerId, bundle);
    console.log(`📋 [${this.agentId}] Bundle de ${peerId} registrado`);
  }

  /**
   * Estabelece sessão segura com peer (como iniciador)
   */
  async establishSession(peerId: string): Promise<void> {
    const peerBundle = this.peerPublicBundles.get(peerId);
    if (!peerBundle) {
      throw new Error(`Bundle de ${peerId} não encontrado`);
    }

    // Gerar chave efêmera para X3DH
    const ephemeralKey = generateX25519KeyPair();

    // Executar X3DH como Alice
    const sharedSecret = performX3DHAsInitiator(
      this.identityKey,
      ephemeralKey,
      peerBundle
    );

    // Inicializar Double Ratchet
    const ratchet = new DoubleRatchet();
    ratchet.initializeAsAlice(sharedSecret, peerBundle.signedPreKey);

    this.sessions.set(peerId, ratchet);

    // Limpar chaves temporárias
    ephemeralKey.privateKey.fill(0);

    console.log(`🔗 [${this.agentId}] Sessão E2EE estabelecida com ${peerId}`);
  }

  /**
   * Aceita sessão segura (como receptor)
   */
  async acceptSession(
    peerId: string,
    senderIdentityKey: Buffer,
    senderEphemeralKey: Buffer
  ): Promise<Buffer> {
    // Executar X3DH como Bob
    const sharedSecret = this.keyBundle.performX3DHAsReceiver(
      senderEphemeralKey,
      senderIdentityKey,
      true
    );

    // Inicializar Double Ratchet
    const ratchet = new DoubleRatchet();
    ratchet.initializeAsBob(sharedSecret);

    this.sessions.set(peerId, ratchet);

    console.log(`🔗 [${this.agentId}] Sessão E2EE aceita de ${peerId}`);

    return ratchet.getPublicKey();
  }

  /**
   * Envia mensagem encriptada
   */
  async sendMessage(peerId: string, content: string): Promise<SignalMessage> {
    const session = this.sessions.get(peerId);
    if (!session) {
      throw new Error(`Sessão com ${peerId} não estabelecida`);
    }

    const { header, ciphertext, nonce } = session.ratchetEncrypt(content);

    const message: SignalMessage = {
      from: this.agentId,
      to: peerId,
      messageId: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      header,
      ciphertext: ciphertext.toString('hex'),
      nonce: nonce.toString('hex'),
      jwt: this.token || undefined
    };

    this.messageHistory.push(message);
    console.log(`📤 [${this.agentId}] → [${peerId}] (E2EE): [${content.length} chars encrypted]`);

    return message;
  }

  /**
   * Recebe e decripta mensagem
   */
  async receiveMessage(message: SignalMessage): Promise<string> {
    // Verificar JWT se presente
    if (message.jwt) {
      try {
        await this.authority.verifyToken(message.jwt);
      } catch (error) {
        console.warn(`⚠️ [${this.agentId}] JWT inválido de ${message.from}`);
      }
    }

    const session = this.sessions.get(message.from);
    if (!session) {
      throw new Error(`Sessão com ${message.from} não encontrada`);
    }

    const ciphertext = Buffer.from(message.ciphertext, 'hex');
    const nonce = Buffer.from(message.nonce, 'hex');

    const plaintext = session.ratchetDecrypt(message.header, ciphertext, nonce);

    this.messageHistory.push(message);
    console.log(`📥 [${this.agentId}] ← [${message.from}] (E2EE): ${plaintext}`);

    this.emit('message', { from: message.from, content: plaintext, message });

    return plaintext;
  }

  getMessageHistory(): SignalMessage[] {
    return [...this.messageHistory];
  }

  getIdentityPublicKey(): Buffer {
    return this.identityKey.publicKey;
  }
}

// ============================================================================
// Demonstração
// ============================================================================

async function demonstrateSignalE2EE() {
  console.log('🚀 Demonstração de Signal Protocol E2EE para Agentes\n');
  console.log('═'.repeat(60));

  // 1. Criar autoridade de tokens
  const tokenAuthority = new TokenAuthority();
  console.log('✅ Token Authority criada\n');

  // 2. Criar agentes
  const agentAlpha = new SignalE2EEAgent('agent-alpha', tokenAuthority, ['reasoning']);
  const agentBeta = new SignalE2EEAgent('agent-beta', tokenAuthority, ['analysis']);

  await agentAlpha.initialize();
  await agentBeta.initialize();
  console.log('');

  // 3. Trocar bundles públicos (simulando um servidor de key distribution)
  console.log('📦 Trocando bundles de chaves públicas...');
  const alphaBundle = agentAlpha.getPublicKeyBundle();
  const betaBundle = agentBeta.getPublicKeyBundle();

  agentAlpha.registerPeerBundle('agent-beta', betaBundle);
  agentBeta.registerPeerBundle('agent-alpha', alphaBundle);
  console.log('');

  // 4. Alpha estabelece sessão com Beta
  console.log('🔐 Estabelecendo sessão E2EE...');
  await agentAlpha.establishSession('agent-beta');
  
  // Beta aceita a sessão (em produção, isso seria feito via primeira mensagem)
  await agentBeta.acceptSession(
    'agent-alpha',
    agentAlpha.getIdentityPublicKey(),
    agentAlpha.getPublicKeyBundle().signedPreKey
  );
  console.log('');

  // 5. Trocar mensagens encriptadas
  console.log('💬 Iniciando conversa E2EE...\n');
  console.log('─'.repeat(60));

  // Alpha envia primeira mensagem
  const msg1 = await agentAlpha.sendMessage(
    'agent-beta',
    'Olá Beta! Esta mensagem está encriptada com Signal Protocol.'
  );
  await agentBeta.receiveMessage(msg1);

  console.log('');

  // Beta responde
  const msg2 = await agentBeta.sendMessage(
    'agent-alpha',
    'Olá Alpha! Recebi sua mensagem com Perfect Forward Secrecy!'
  );
  await agentAlpha.receiveMessage(msg2);

  console.log('');

  // Alpha envia outra mensagem
  const msg3 = await agentAlpha.sendMessage(
    'agent-beta',
    'O Double Ratchet garante que cada mensagem usa uma chave única.'
  );
  await agentBeta.receiveMessage(msg3);

  console.log('');

  // Beta responde novamente
  const msg4 = await agentBeta.sendMessage(
    'agent-alpha',
    'Exatamente! E temos Post-Compromise Security também.'
  );
  await agentAlpha.receiveMessage(msg4);

  console.log('');
  console.log('─'.repeat(60));

  // 6. Mostrar resumo
  console.log('\n📊 Resumo da Demonstração:\n');
  console.log('🔒 Propriedades de Segurança:');
  console.log('   • Perfect Forward Secrecy (PFS)');
  console.log('   • Post-Compromise Security (PCS)');
  console.log('   • Chaves únicas por mensagem');
  console.log('   • Deniability (negabilidade)');
  console.log('');
  console.log('🔧 Algoritmos Utilizados:');
  console.log('   • X3DH para key agreement inicial');
  console.log('   • X25519 para Diffie-Hellman');
  console.log('   • HKDF-SHA256 para derivação de chaves');
  console.log('   • AES-256-GCM para encriptação');
  console.log('   • Double Ratchet para gestão de chaves');
  console.log('');
  console.log(`📨 Total de mensagens trocadas: ${agentAlpha.getMessageHistory().length * 2}`);
  console.log('');
  console.log('✅ Demonstração concluída!');
}

// ============================================================================
// Combinação com mTLS (demonstração conceitual)
// ============================================================================

async function demonstrateCombinedSecurity() {
  console.log('\n');
  console.log('═'.repeat(60));
  console.log('🔐 Signal E2EE + mTLS: Defesa em Profundidade');
  console.log('═'.repeat(60));
  console.log('');
  console.log('Quando combinados, você obtém:');
  console.log('');
  console.log('┌─────────────────────────────────────────────────────────┐');
  console.log('│  CAMADA           │  PROTOCOLO  │  PROTEÇÃO             │');
  console.log('├─────────────────────────────────────────────────────────┤');
  console.log('│  Transporte       │  mTLS       │  Autenticação mútua   │');
  console.log('│                   │             │  Canal seguro         │');
  console.log('│                   │             │  Anti-MITM            │');
  console.log('├─────────────────────────────────────────────────────────┤');
  console.log('│  Aplicação        │  Signal E2E │  Forward Secrecy      │');
  console.log('│                   │             │  Post-Compromise Sec  │');
  console.log('│                   │             │  Deniability          │');
  console.log('├─────────────────────────────────────────────────────────┤');
  console.log('│  Contexto         │  JWT        │  Identity claims      │');
  console.log('│                   │             │  Authorization        │');
  console.log('│                   │             │  Expiration           │');
  console.log('└─────────────────────────────────────────────────────────┘');
  console.log('');
  console.log('💡 Benefícios da combinação:');
  console.log('   1. Mesmo que mTLS seja comprometido, E2EE protege o conteúdo');
  console.log('   2. Mesmo que E2EE seja comprometido, mTLS protege o canal');
  console.log('   3. JWT adiciona contexto e autorização independente');
  console.log('   4. Defesa em profundidade reduz superfície de ataque');
  console.log('');
}

// Executar demonstrações
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateSignalE2EE()
    .then(demonstrateCombinedSecurity)
    .catch(console.error);
}

export {
  SignalE2EEAgent,
  DoubleRatchet,
  X3DHKeyBundle,
  TokenAuthority,
  SignalMessage,
  KeyBundle
};
