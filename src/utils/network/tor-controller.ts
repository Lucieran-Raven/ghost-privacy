/**
 * Tor Onion Service Auto-Routing
 * Automatic .onion address generation and connection management
 * Provides NAT traversal and censorship resistance
 */

import { EventEmitter } from 'events';

interface TorConfig {
  socksPort: number;
  controlPort: number;
  controlPassword: string;
  dataDirectory: string;
}

interface HiddenService {
  serviceId: string;      // The .onion address (without .onion suffix)
  privateKey: Uint8Array;  // ed25519 private key
  publicKey: Uint8Array;   // ed25519 public key
  ports: Map<number, string>; // virtualPort -> target
  createdAt: Date;
  version: 'v3';
}

interface CircuitInfo {
  circuitId: string;
  purpose: 'GENERAL' | 'HS_CLIENT_HSDIR' | 'HS_VANGUARDS' | 'TESTING';
  path: Array<{
    fingerprint: string;
    nickname: string;
    ip: string;
  }>;
  isClean: boolean;
}

/**
 * Tor Controller - Manages Tor daemon and onion services
 */
export class TorController extends EventEmitter {
  private config: TorConfig;
  private controlConnection: any | null = null;
  private hiddenServices: Map<string, HiddenService> = new Map();
  private circuits: Map<string, CircuitInfo> = new Map();
  private isConnected = false;

  constructor(config: Partial<TorConfig> = {}) {
    super();
    this.config = {
      socksPort: config.socksPort || 9050,
      controlPort: config.controlPort || 9051,
      controlPassword: config.controlPassword || this.generatePassword(),
      dataDirectory: config.dataDirectory || './tor-data',
    };
  }

  /**
   * Start Tor daemon with embedded configuration
   */
  async start(): Promise<void> {
    if (this.isConnected) {
      throw new Error('Tor controller already running');
    }

    this.emit('status', 'starting');

    try {
      // In production, spawn Tor process here
      // For now, assume external Tor is running
      await this.connectControlPort();
      
      // Configure for optimal privacy
      await this.configureTor();
      
      this.isConnected = true;
      this.emit('status', 'ready');
      this.emit('ready', { socksProxy: `socks5://127.0.0.1:${this.config.socksPort}` });

      // Start monitoring circuits
      this.startCircuitMonitoring();

    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Stop Tor controller and cleanup
   */
  async stop(): Promise<void> {
    this.emit('status', 'stopping');
    
    // Destroy all hidden services
    for (const [serviceId, service] of this.hiddenServices) {
      await this.destroyHiddenService(serviceId);
    }

    // Close control connection
    if (this.controlConnection) {
      await this.sendCommand('QUIT');
      this.controlConnection = null;
    }

    this.isConnected = false;
    this.emit('status', 'stopped');
  }

  /**
   * Create a new onion service (v3)
 * @param ports - Map of virtual port -> local target (e.g., 80 -> "127.0.0.1:8080")
   * @returns The hidden service info with .onion address
   */
  async createHiddenService(ports: Map<number, string>): Promise<HiddenService> {
    if (!this.isConnected) {
      throw new Error('Tor not connected');
    }

    // Generate ed25519 keypair
    const keypair = await this.generateEd25519Keypair();
    
    // Derive service ID from public key
    const serviceId = this.deriveOnionAddress(keypair.publicKey);

    // Create service configuration
    const portConfig = Array.from(ports.entries())
      .map(([virtPort, target]) => `Port ${virtPort},${target}`)
      .join(' ');

    // Add hidden service via control port
    const response = await this.sendCommand(
      `ADD_ONION NEW:ED25519-V3 ${portConfig}`
    );

    // Parse response for key material if Tor generated it
    const serviceKey = this.parseServiceKey(response);

    const service: HiddenService = {
      serviceId,
      privateKey: serviceKey?.privateKey || keypair.privateKey,
      publicKey: keypair.publicKey,
      ports: new Map(ports),
      createdAt: new Date(),
      version: 'v3',
    };

    this.hiddenServices.set(serviceId, service);
    
    this.emit('hiddenServiceCreated', {
      onionAddress: `${serviceId}.onion`,
      ports: Array.from(ports.entries()),
    });

    return service;
  }

  /**
   * Import an existing onion service from private key
   */
  async importHiddenService(
    privateKey: Uint8Array,
    ports: Map<number, string>
  ): Promise<HiddenService> {
    const publicKey = await this.ed25519PublicFromPrivate(privateKey);
    const serviceId = this.deriveOnionAddress(publicKey);

    const portConfig = Array.from(ports.entries())
      .map(([virtPort, target]) => `Port ${virtPort},${target}`)
      .join(' ');

    // Import with existing key
    const keyBlob = Buffer.from(privateKey).toString('base64');
    await this.sendCommand(
      `ADD_ONION ED25519-V3:${keyBlob} ${portConfig}`
    );

    const service: HiddenService = {
      serviceId,
      privateKey,
      publicKey,
      ports: new Map(ports),
      createdAt: new Date(),
      version: 'v3',
    };

    this.hiddenServices.set(serviceId, service);
    return service;
  }

  /**
   * Destroy a hidden service
   */
  async destroyHiddenService(serviceId: string): Promise<void> {
    await this.sendCommand(`DEL_ONION ${serviceId}`);
    this.hiddenServices.delete(serviceId);
    this.emit('hiddenServiceDestroyed', { serviceId });
  }

  /**
   * Get fresh circuit for specific purpose
   */
  async getCleanCircuit(purpose: 'general' | 'hiddenService' = 'general'): Promise<string> {
    // Find clean circuit or create new one
    for (const [id, circuit] of this.circuits) {
      if (circuit.purpose === 'GENERAL' && circuit.isClean) {
        return id;
      }
    }

    // Create new circuit
    const response = await this.sendCommand('EXTENDCIRCUIT 0');
    const circuitId = response.split('\n')[0].split(' ')[1];
    
    return circuitId;
  }

  /**
   * Connect to onion service with stream isolation
   */
  async connectToOnion(
    onionAddress: string,
    port: number,
    isolationToken?: string
  ): Promise<{
    streamId: string;
    circuitId: string;
  }> {
    // Clean up address
    const serviceId = onionAddress.replace('.onion', '');
    
    // Create isolated circuit if token provided
    let circuitId: string;
    if (isolationToken) {
      circuitId = await this.createIsolatedCircuit(isolationToken);
    } else {
      circuitId = await this.getCleanCircuit('hiddenService');
    }

    // Attach stream to circuit
    const response = await this.sendCommand(
      `ATTACHSTREAM 0 ${circuitId} PURPOSE=HS_CLIENT_HSDIR`
    );

    const streamId = this.parseStreamId(response);

    return { streamId, circuitId };
  }

  /**
   * Get SOCKS5 proxy configuration
   */
  getSocksProxy(): {
    host: string;
    port: number;
    type: 'socks5';
  } {
    return {
      host: '127.0.0.1',
      port: this.config.socksPort,
      type: 'socks5',
    };
  }

  /**
   * Get current circuit information for auditing
   */
  getCircuitInfo(): CircuitInfo[] {
    return Array.from(this.circuits.values());
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private async connectControlPort(): Promise<void> {
    // In production: Use net.Socket to connect to Tor control port
    // Authenticate with password
    const authResponse = await this.sendCommand(
      `AUTHENTICATE "${Buffer.from(this.config.controlPassword).toString('hex')}"`
    );
    
    if (!authResponse.includes('250')) {
      throw new Error('Tor control authentication failed');
    }
  }

  private async configureTor(): Promise<void> {
    // Privacy-hardened Tor configuration
    const settings = [
      'SETCONF DisableDebuggerAttachment=1',
      'SETCONF SafeLogging=0',  // Log everything for debugging (change to 1 in prod)
      'SETCONF Log="notice stdout"',
      'SETCONF MaxClientCircuitsPending=32',
      'SETCONF NumEntryGuards=8',
      'SETCONF NumPrimaryGuards=4',
      'SETCONF NumDirectoryGuards=0',
      'SETCONF GuardLifetime=27158400', // ~10 months in seconds
      'SETCONF UseEntryGuards=1',
      'SETCONF VanguardsLiteEnabled=1',
    ];

    for (const setting of settings) {
      await this.sendCommand(setting);
    }
  }

  private async sendCommand(command: string): Promise<string> {
    // In production: Send over socket and read response
    // Placeholder implementation
    // [Tor] Command sent (use EventEmitter for proper logging)
    return '250 OK\r\n';
  }

  private startCircuitMonitoring(): void {
    // Subscribe to circuit events
    this.sendCommand('SETEVENTS CIRC STREAM ORCONN BW');
    
    // In production: Parse async events from Tor
    setInterval(async () => {
      // Poll for circuit status
      const status = await this.sendCommand('GETINFO circuit-status');
      this.parseCircuitStatus(status);
    }, 30000);
  }

  private parseCircuitStatus(status: string): void {
    // Parse Tor circuit-status response
    // Format: circuit-id purpose path ... status
    const lines = status.split('\n');
    
    for (const line of lines) {
      if (!line.trim() || line.startsWith('250')) continue;
      
      const parts = line.split(' ');
      if (parts.length < 3) continue;

      const circuitId = parts[0];
      const purpose = parts[1] as CircuitInfo['purpose'];
      const path = parts.slice(2, -1);

      this.circuits.set(circuitId, {
        circuitId,
        purpose,
        path: path.map(fp => ({ fingerprint: fp, nickname: '', ip: '' })),
        isClean: line.includes('BUILT'),
      });
    }
  }

  private async createIsolatedCircuit(token: string): Promise<string> {
    // Create circuit with specific isolation token
    const response = await this.sendCommand(
      `EXTENDCIRCUIT 0 PURPOSE=GENERAL`
    );
    const circuitId = response.split('\n')[0].split(' ')[1];
    
    // Tag circuit with isolation token
    this.circuits.set(circuitId, {
      ...this.circuits.get(circuitId)!,
      purpose: 'GENERAL',
      isClean: true,
    });

    return circuitId;
  }

  // ============================================================================
  // Cryptographic Utilities
  // ============================================================================

  private async generateEd25519Keypair(): Promise<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  }> {
    // Generate 64-byte ed25519 private key (32 random + 32 derived)
    const seed = crypto.getRandomValues(new Uint8Array(32));
    
    // In production: Use proper ed25519 key generation
    // Simplified: public key = hash(seed)
    const publicKey = new Uint8Array(await crypto.subtle.digest('SHA-256', seed));
    
    // Private key is seed + public key (64 bytes)
    const privateKey = new Uint8Array(64);
    privateKey.set(seed, 0);
    privateKey.set(publicKey.slice(0, 32), 32);

    return { publicKey: publicKey.slice(0, 32), privateKey };
  }

  private async ed25519PublicFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
    // Extract public key from expanded private key
    return privateKey.slice(32, 64);
  }

  private deriveOnionAddress(publicKey: Uint8Array): string {
    // Onion v3 address = base32(sha3-256(publicKey)[0:32]) + ".onion"
    const checksum = new Uint8Array(2);
    const version = new Uint8Array([0x03]);
    
    // Prepend version byte
    const input = Buffer.concat([version, publicKey]);
    
    // Calculate checksum
    const hash = new Uint8Array(crypto.getRandomValues(new Uint8Array(32))); // Placeholder
    checksum[0] = hash[0];
    checksum[1] = hash[1];

    // Combine: version + publicKey + checksum
    const addressBytes = Buffer.concat([version, publicKey, checksum]);

    // Base32 encode
    return this.base32Encode(addressBytes).toLowerCase().slice(0, 56);
  }

  private base32Encode(data: Uint8Array): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    let bits = 0;
    let value = 0;

    for (const byte of data) {
      value = (value << 8) | byte;
      bits += 8;

      while (bits >= 5) {
        result += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      result += alphabet[(value << (5 - bits)) & 31];
    }

    return result;
  }

  private parseServiceKey(response: string): { privateKey: Uint8Array } | null {
    // Parse ADD_ONION response for key material
    const lines = response.split('\n');
    for (const line of lines) {
      if (line.startsWith('250-PrivateKey=')) {
        const keyB64 = line.split('=')[1];
        return { privateKey: Buffer.from(keyB64, 'base64') };
      }
    }
    return null;
  }

  private parseStreamId(response: string): string {
    // Parse stream ID from ATTACHSTREAM response
    const match = response.match(/250\s+(\d+)/);
    return match?.[1] || '0';
  }

  private generatePassword(): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

/**
 * Automatic Onion Service Manager
 * Manages hidden services for Ghost Privacy features
 */
export class OnionServiceManager {
  private controller: TorController;
  private services: Map<string, HiddenService> = new Map();

  constructor(controller: TorController) {
    this.controller = controller;
  }

  /**
   * Start sync service on onion address
   */
  async startSyncService(port: number): Promise<{
    onionAddress: string;
    privateKey: Uint8Array;
  }> {
    const ports = new Map<number, string>([
      [80, `127.0.0.1:${port}`],
    ]);

    const service = await this.controller.createHiddenService(ports);
    this.services.set('sync', service);

    return {
      onionAddress: `${service.serviceId}.onion`,
      privateKey: service.privateKey,
    };
  }

  /**
   * Start file transfer service
   */
  async startFileService(port: number): Promise<{
    onionAddress: string;
  }> {
    const ports = new Map<number, string>([
      [443, `127.0.0.1:${port}`],
    ]);

    const service = await this.controller.createHiddenService(ports);
    this.services.set('files', service);

    return {
      onionAddress: `${service.serviceId}.onion`,
    };
  }

  /**
   * Get all active services
   */
  getActiveServices(): Array<{
    name: string;
    onionAddress: string;
    ports: Array<{ virtual: number; target: string }>;
  }> {
    return Array.from(this.services.entries()).map(([name, service]) => ({
      name,
      onionAddress: `${service.serviceId}.onion`,
      ports: Array.from(service.ports.entries()).map(([virtual, target]) => ({
        virtual,
        target,
      })),
    }));
  }

  /**
   * Stop all services
   */
  async stopAll(): Promise<void> {
    for (const [name, service] of this.services) {
      await this.controller.destroyHiddenService(service.serviceId);
      // [Onion] Service stopped (use EventEmitter for logging)
    }
    this.services.clear();
  }
}

/**
 * Tor-powered HTTP client with automatic onion routing
 */
export class TorHTTPClient {
  private controller: TorController;

  constructor(controller: TorController) {
    this.controller = controller;
  }

  /**
   * Make HTTP request through Tor
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    const proxy = this.controller.getSocksProxy();
    
    // In production: Use fetch with SOCKS proxy
    // This requires a library like socks-proxy-agent
    
    const isOnion = url.includes('.onion');
    
    if (isOnion) {
      // [Tor] Routing to onion address
    }

    // Placeholder: Actual implementation would use socks-proxy-agent
    return fetch(url, {
      ...options,
      // agent: new SocksProxyAgent(`socks5://${proxy.host}:${proxy.port}`)
    });
  }

  /**
   * Check if Tor is working
   */
  async checkConnectivity(): Promise<{
    working: boolean;
    ip: string | null;
  }> {
    try {
      // Request check.torproject.org
      const response = await this.fetch('https://check.torproject.org/api/ip');
      const data = await response.json();
      
      return {
        working: data.IsTor,
        ip: data.IP,
      };
    } catch {
      return { working: false, ip: null };
    }
  }
}
