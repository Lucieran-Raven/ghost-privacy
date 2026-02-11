/**
 * IPFS/Filecoin Decentralized Storage
 * Store large files in distributed network with content addressing
 * 
 * Features:
 * - Content-addressed storage (CID-based retrieval)
 * - Filecoin persistence for permanent storage
 * - Client-side encryption before upload
 * - Pin management for availability
 */

import { Buffer } from 'buffer';

interface IPFSConfig {
  apiUrl: string;
  gatewayUrl: string;
  filecoinRpcUrl?: string;
  walletAddress?: string;
}

interface FilecoinDeal {
  dealId: number;
  provider: string;
  startEpoch: number;
  endEpoch: number;
  pricePerEpoch: bigint;
  clientAddress: string;
  pieceCID: string;
  status: 'pending' | 'active' | 'expired' | 'slashed';
}

interface StorageStats {
  pinnedCids: number;
  repoSize: bigint;
  storageMax: bigint;
  bandwidthIn: bigint;
  bandwidthOut: bigint;
}

interface EncryptedBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  originalCID: string;
  encryptionKeyHash: Uint8Array;
}

/**
 * IPFS Client with Filecoin persistence
 */
export class IPFSStorage {
  private config: IPFSConfig;
  private pinnedCids: Set<string> = new Set();
  private filecoinDeals: Map<string, FilecoinDeal[]> = new Map();

  constructor(config: IPFSConfig) {
    this.config = {
      apiUrl: config.apiUrl || 'http://localhost:5001',
      gatewayUrl: config.gatewayUrl || 'https://ipfs.io',
      ...config,
    };
  }

  /**
   * Upload data to IPFS with client-side encryption
   * 
   * @param data - Raw file data
   * @param encrypt - Whether to encrypt before upload (recommended)
   * @returns CID and encryption key (if encrypted)
   */
  async upload(
    data: Uint8Array,
    options: {
      encrypt?: boolean;
      filename?: string;
      pin?: boolean;
    } = {}
  ): Promise<{
    cid: string;
    encryptionKey?: Uint8Array;
    size: number;
  }> {
    const { encrypt = true, filename = 'blob', pin = true } = options;

    let uploadData: Uint8Array;
    let encryptionKey: Uint8Array | undefined;

    if (encrypt) {
      // Generate random encryption key
      encryptionKey = crypto.getRandomValues(new Uint8Array(32));
      
      // Encrypt data with AES-GCM
      const encrypted = await this.encryptAESGCM(data, encryptionKey);
      
      // Wrap with metadata
      const metadata = {
        version: 'ghost-v1',
        encrypted: true,
        iv: Buffer.from(encrypted.iv).toString('base64'),
        tag: Buffer.from(encrypted.tag).toString('base64'),
        originalSize: data.length,
        filename,
        timestamp: Date.now(),
      };

      uploadData = Buffer.concat([
        Buffer.from(JSON.stringify(metadata) + '\n'),
        Buffer.from(encrypted.ciphertext),
      ]);
    } else {
      uploadData = Buffer.from(data);
    }

    // Upload to IPFS via HTTP API
    const cid = await this.ipfsAdd(uploadData, { pin });

    if (pin) {
      this.pinnedCids.add(cid);
    }

    this.emit('uploaded', {
      cid,
      size: uploadData.length,
      encrypted: encrypt,
    });

    return {
      cid,
      encryptionKey,
      size: uploadData.length,
    };
  }

  /**
   * Download and decrypt data from IPFS
   */
  async download(
    cid: string,
    encryptionKey?: Uint8Array
  ): Promise<{
    data: Uint8Array;
    metadata: any;
  }> {
    // Fetch from IPFS
    const response = await fetch(`${this.config.gatewayUrl}/ipfs/${cid}`);
    
    if (!response.ok) {
      throw new Error(`IPFS download failed: ${response.status}`);
    }

    const buffer = new Uint8Array(await response.arrayBuffer());

    // Parse metadata
    const newlineIndex = buffer.indexOf(0x0a); // '\n'
    if (newlineIndex === -1) {
      throw new Error('Invalid format: no metadata delimiter');
    }

    const metadataJson = new TextDecoder().decode(buffer.slice(0, newlineIndex));
    const metadata = JSON.parse(metadataJson);
    const ciphertext = buffer.slice(newlineIndex + 1);

    let data: Uint8Array;

    if (metadata.encrypted) {
      if (!encryptionKey) {
        throw new Error('Encryption key required for encrypted content');
      }

      const iv = Buffer.from(metadata.iv, 'base64');
      const tag = Buffer.from(metadata.tag, 'base64');
      data = await this.decryptAESGCM(
        { ciphertext, iv, tag },
        encryptionKey
      );
    } else {
      data = ciphertext;
    }

    return { data, metadata };
  }

  /**
   * Create Filecoin storage deal for permanent persistence
   * 
   * @param cid - IPFS CID to persist
   * @param durationDays - Storage duration in days
   * @param replication - Number of storage providers (1-10)
   */
  async createFilecoinDeal(
    cid: string,
    durationDays: number = 365,
    replication: number = 3
  ): Promise<FilecoinDeal[]> {
    if (!this.config.filecoinRpcUrl) {
      throw new Error('Filecoin RPC not configured');
    }

    // Calculate epochs (30 seconds per epoch)
    const startEpoch = await this.getCurrentEpoch();
    const endEpoch = startEpoch + Math.floor((durationDays * 24 * 60 * 60) / 30);

    // Find storage providers
    const providers = await this.findStorageProviders(cid, replication);
    
    const deals: FilecoinDeal[] = [];

    for (const provider of providers) {
      // Calculate price
      const pricePerEpoch = await this.estimatePrice(cid, provider, durationDays);

      const deal: FilecoinDeal = {
        dealId: 0, // Will be set on-chain
        provider: provider.address,
        startEpoch,
        endEpoch,
        pricePerEpoch,
        clientAddress: this.config.walletAddress || '',
        pieceCID: cid,
        status: 'pending',
      };

      // Propose deal to provider
      const dealId = await this.proposeDeal(deal);
      deal.dealId = dealId;
      
      deals.push(deal);
    }

    // Store deal info
    this.filecoinDeals.set(cid, deals);

    this.emit('dealsCreated', { cid, deals });

    return deals;
  }

  /**
   * Check Filecoin deal status
   */
  async checkDealStatus(cid: string): Promise<FilecoinDeal[]> {
    const deals = this.filecoinDeals.get(cid) || [];
    
    const updatedDeals = await Promise.all(
      deals.map(async (deal) => {
        const status = await this.queryDealOnChain(deal.dealId);
        return { ...deal, status };
      })
    );

    this.filecoinDeals.set(cid, updatedDeals);
    return updatedDeals;
  }

  /**
   * Pin CID to local node for availability
   */
  async pin(cid: string): Promise<void> {
    await this.ipfsPin(cid);
    this.pinnedCids.add(cid);
  }

  /**
   * Unpin CID to free space
   */
  async unpin(cid: string): Promise<void> {
    await this.ipfsUnpin(cid);
    this.pinnedCids.delete(cid);
  }

  /**
   * Get storage statistics
   */
  async getStats(): Promise<StorageStats> {
    const response = await fetch(`${this.config.apiUrl}/api/v0/stats/repo`);
    const data = await response.json();

    const bwResponse = await fetch(`${this.config.apiUrl}/api/v0/stats/bw`);
    const bwData = await bwResponse.json();

    return {
      pinnedCids: this.pinnedCids.size,
      repoSize: BigInt(data.RepoSize || 0),
      storageMax: BigInt(data.StorageMax || 0),
      bandwidthIn: BigInt(bwData.TotalIn || 0),
      bandwidthOut: BigInt(bwData.TotalOut || 0),
    };
  }

  /**
   * Garbage collect unpinned blocks
   */
  async garbageCollect(): Promise<{
    freed: bigint;
    deleted: number;
  }> {
    const response = await fetch(
      `${this.config.apiUrl}/api/v0/repo/gc`,
      { method: 'POST' }
    );
    
    const results = await response.json();
    
    let freed = BigInt(0);
    let deleted = 0;

    for (const result of results) {
      freed += BigInt(result.Size || 0);
      deleted++;
    }

    return { freed, deleted };
  }

  /**
   * Resolve IPNS name to CID
   */
  async resolveIPNS(name: string): Promise<string> {
    const response = await fetch(
      `${this.config.apiUrl}/api/v0/name/resolve?arg=${encodeURIComponent(name)}`
    );
    
    const data = await response.json();
    return data.Path.replace('/ipfs/', '');
  }

  /**
   * Publish CID to IPNS for mutable references
   */
  async publishToIPNS(
    cid: string,
    keyName?: string
  ): Promise<string> {
    let url = `${this.config.apiUrl}/api/v0/name/publish?arg=${cid}`;
    
    if (keyName) {
      url += `&key=${keyName}`;
    }

    const response = await fetch(url, { method: 'POST' });
    const data = await response.json();

    return data.Name; // IPNS address
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private async ipfsAdd(
    data: Uint8Array,
    options: { pin: boolean }
  ): Promise<string> {
    const formData = new FormData();
    formData.append('file', new Blob([data]));

    let url = `${this.config.apiUrl}/api/v0/add?cid-version=1&hash=sha2-256`;
    if (options.pin) {
      url += '&pin=true';
    }

    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`IPFS add failed: ${response.status}`);
    }

    const result = await response.json();
    return result.Hash;
  }

  private async ipfsPin(cid: string): Promise<void> {
    const response = await fetch(
      `${this.config.apiUrl}/api/v0/pin/add?arg=${cid}`,
      { method: 'POST' }
    );

    if (!response.ok) {
      throw new Error(`IPFS pin failed: ${response.status}`);
    }
  }

  private async ipfsUnpin(cid: string): Promise<void> {
    const response = await fetch(
      `${this.config.apiUrl}/api/v0/pin/rm?arg=${cid}`,
      { method: 'POST' }
    );

    if (!response.ok) {
      throw new Error(`IPFS unpin failed: ${response.status}`);
    }
  }

  private async encryptAESGCM(
    plaintext: Uint8Array,
    key: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array }> {
    // Generate random IV (12 bytes for AES-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12)) as Uint8Array;
    
    // Import key for WebCrypto
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    
    // Encrypt using AES-GCM (WebCrypto handles authentication tag internally)
    const ciphertextWithTag = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      plaintext
    );
    
    // Split ciphertext and authentication tag (last 16 bytes)
    const encrypted = new Uint8Array(ciphertextWithTag);
    const ciphertext = encrypted.slice(0, -16);
    const tag = encrypted.slice(-16);

    return { ciphertext, iv, tag };
  }

  private async decryptAESGCM(
    encrypted: { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array },
    key: Uint8Array
  ): Promise<Uint8Array> {
    const { ciphertext, iv, tag } = encrypted;
    
    // Reconstruct ciphertext + tag for WebCrypto
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);
    
    // Import key for WebCrypto
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    // Decrypt (will throw if authentication tag is invalid)
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      combined
    );

    return new Uint8Array(plaintext);
  }

  private async getCurrentEpoch(): Promise<number> {
    const response = await fetch(`${this.config.filecoinRpcUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'Filecoin.ChainHead',
        params: [],
        id: 1,
      }),
    });

    const data = await response.json();
    return data.result.Height;
  }

  private async findStorageProviders(
    cid: string,
    count: number
  ): Promise<Array<{ address: string; price: bigint }>> {
    // Query Filecoin for available storage providers
    const response = await fetch(`${this.config.filecoinRpcUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'Filecoin.StateListMiners',
        params: [null],
        id: 1,
      }),
    });

    const data = await response.json();
    const miners = data.result.slice(0, count);

    return miners.map((address: string) => ({
      address,
      price: BigInt(0), // Will be queried per deal
    }));
  }

  private async estimatePrice(
    cid: string,
    provider: { address: string },
    durationDays: number
  ): Promise<bigint> {
    // Query provider's asking price
    const response = await fetch(`${this.config.filecoinRpcUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'Filecoin.StateMinerInfo',
        params: [provider.address, null],
        id: 1,
      }),
    });

    const data = await response.json();
    // Simplified pricing calculation
    const basePrice = BigInt('1000000000000000'); // 0.001 FIL per epoch
    const epochs = BigInt(durationDays * 24 * 60 * 2); // ~30s epochs
    
    return basePrice * epochs;
  }

  private async proposeDeal(deal: FilecoinDeal): Promise<number> {
    // Send deal proposal via Lotus API
    const response = await fetch(`${this.config.filecoinRpcUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'Filecoin.ClientStartDeal',
        params: [{
          Data: {
            TransferType: 'graphsync',
            Root: { '/': deal.pieceCID },
            PieceCid: null,
            PieceSize: 0,
          },
          Wallet: deal.clientAddress,
          Miner: deal.provider,
          EpochPrice: deal.pricePerEpoch.toString(),
          MinBlocksDuration: (deal.endEpoch - deal.startEpoch).toString(),
        }],
        id: 1,
      }),
    });

    const data = await response.json();
    return data.result; // Deal ID
  }

  private async queryDealOnChain(dealId: number): Promise<FilecoinDeal['status']> {
    const response = await fetch(`${this.config.filecoinRpcUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'Filecoin.StateMarketStorageDeal',
        params: [dealId, null],
        id: 1,
      }),
    });

    const data = await response.json();
    const deal = data.result?.Proposal;
    
    if (!deal) return 'expired';
    
    const currentEpoch = await this.getCurrentEpoch();
    
    if (currentEpoch < deal.StartEpoch) return 'pending';
    if (currentEpoch > deal.EndEpoch) return 'expired';
    
    return 'active';
  }

  private emit(event: string, data: any): void {
    // Event emitter implementation - use proper event system instead of console
    // [IPFS] Event: {event}, data: {data}
  }
}

/**
 * Ghost Privacy File Storage API
 * High-level interface for file operations
 */
export class GhostFileStorage {
  private ipfs: IPFSStorage;
  private fileIndex: Map<string, {
    cid: string;
    encryptionKey: Uint8Array;
    uploadedAt: Date;
    filecoinDeals?: FilecoinDeal[];
  }> = new Map();

  constructor(ipfs: IPFSStorage) {
    this.ipfs = ipfs;
  }

  /**
   * Upload file with automatic encryption
   */
  async uploadFile(
    fileId: string,
    data: Uint8Array,
    options: {
      persistToFilecoin?: boolean;
      filecoinDuration?: number;
    } = {}
  ): Promise<{
    cid: string;
    fileId: string;
  }> {
    const { cid, encryptionKey } = await this.ipfs.upload(data, {
      encrypt: true,
      pin: true,
    });

    this.fileIndex.set(fileId, {
      cid,
      encryptionKey: encryptionKey!,
      uploadedAt: new Date(),
    });

    if (options.persistToFilecoin) {
      const deals = await this.ipfs.createFilecoinDeal(
        cid,
        options.filecoinDuration || 365
      );
      
      const entry = this.fileIndex.get(fileId)!;
      entry.filecoinDeals = deals;
    }

    return { cid, fileId };
  }

  /**
   * Download and decrypt file
   */
  async downloadFile(fileId: string): Promise<Uint8Array> {
    const entry = this.fileIndex.get(fileId);
    if (!entry) {
      throw new Error(`Unknown file: ${fileId}`);
    }

    const { data } = await this.ipfs.download(entry.cid, entry.encryptionKey);
    return data;
  }

  /**
   * Share file via IPNS
   */
  async shareFile(fileId: string): Promise<string> {
    const entry = this.fileIndex.get(fileId);
    if (!entry) {
      throw new Error(`Unknown file: ${fileId}`);
    }

    return await this.ipfs.publishToIPNS(entry.cid, `ghost-${fileId}`);
  }

  /**
   * Get all stored files
   */
  listFiles(): Array<{
    fileId: string;
    cid: string;
    uploadedAt: Date;
    hasFilecoinPersistence: boolean;
  }> {
    return Array.from(this.fileIndex.entries()).map(([fileId, entry]) => ({
      fileId,
      cid: entry.cid,
      uploadedAt: entry.uploadedAt,
      hasFilecoinPersistence: !!entry.filecoinDeals?.length,
    }));
  }
}
