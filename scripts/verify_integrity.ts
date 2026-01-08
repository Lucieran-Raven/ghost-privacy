
/**
 * GHOST INTEGRITY VERIFICATION SUITE
 * 
 * Purpose: comprehensive self-test of cryptographic claims.
 * Usage: npx tsx scripts/verify_integrity.ts
 */

export {};

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// 1. SETUP ENVIRONMENT (Polyfill Web Crypto + Browser Globals for Node.js)
if (typeof globalThis.btoa === 'undefined') {
    globalThis.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
    globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
}
if (typeof globalThis.TextEncoder === 'undefined') {
    const { TextEncoder, TextDecoder } = await import('util');
    // @ts-ignore
    globalThis.TextEncoder = TextEncoder;
    // @ts-ignore
    globalThis.TextDecoder = TextDecoder;
}

// We do this BEFORE importing app code to ensure 'crypto' is available globally
if (!globalThis.crypto) {
    try {
        const nodeCrypto = await import('node:crypto');
        // @ts-ignore
        globalThis.crypto = nodeCrypto.webcrypto;
        process.stdout.write("✅ Web Crypto API polyfilled via node:crypto\n");
    } catch (e) {
        process.stderr.write(`❌ Failed to polyfill crypto: ${String(e)}\n`);
    }
}

// 2. DYNAMIC IMPORTS
// We must use dynamic imports so they evaluate AFTER the polyfill
const { DeniableEncryption } = await import('../src/utils/deniableEncryption');
const { ClientMessageQueue } = await import('../src/utils/clientMessageQueue');

const COLORS = {
    reset: "\x1b[0m",
    green: "\x1b[32m",
    red: "\x1b[31m",
    cyan: "\x1b[36m",
    yellow: "\x1b[33m"
};

const log = (msg: string, color: string = COLORS.reset) => process.stdout.write(`${color}${msg}${COLORS.reset}\n`);

function listFilesRecursive(dir: string): string[] {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const out: string[] = [];
    for (const e of entries) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) {
            out.push(...listFilesRecursive(p));
        } else {
            out.push(p);
        }
    }
    return out;
}

function normalizeText(input: string): string {
    return input.replace(/\r\n/g, '\n');
}

function shouldIgnorePath(p: string): boolean {
    const norm = p.replace(/\\/g, '/');
    return (
        norm.includes('/node_modules/') ||
        norm.includes('/dist/') ||
        norm.includes('/android/app/build/') ||
        norm.includes('/android/.gradle/') ||
        norm.includes('/src-tauri/target/')
    );
}

function computeRepoIntegrityHash(repoRoot: string): string {
    const includeRoots = [
        'package.json',
        'package-lock.json',
        'eslint.config.js',
        'auditor',
        'src',
        'src-tauri/src',
        'src-tauri/Cargo.lock',
        'supabase/functions',
        'supabase/migrations',
        'scripts'
    ];

    const files: string[] = [];
    for (const rel of includeRoots) {
        const abs = path.join(repoRoot, rel);
        if (!fs.existsSync(abs)) continue;
        const st = fs.statSync(abs);
        if (st.isDirectory()) {
            files.push(...listFilesRecursive(abs));
        } else {
            files.push(abs);
        }
    }

    const hashed = files
        .filter((p) => !shouldIgnorePath(p))
        .filter((p) => {
            const name = p.toLowerCase();
            return (
                name.endsWith('.ts') ||
                name.endsWith('.tsx') ||
                name.endsWith('.js') ||
                name.endsWith('.json') ||
                name.endsWith('.sql') ||
                name.endsWith('.rs') ||
                name.endsWith('.toml') ||
                name.endsWith('.lock') ||
                name.endsWith('.md')
            );
        })
        .map((absPath) => {
            const relPath = path.relative(repoRoot, absPath).replace(/\\/g, '/');
            return { absPath, relPath };
        })
        .sort((a, b) => a.relPath.localeCompare(b.relPath));

    const h = createHash('sha256');
    for (const { absPath, relPath } of hashed) {
        const raw = fs.readFileSync(absPath, 'utf8');
        const content = normalizeText(raw);
        h.update(relPath, 'utf8');
        h.update('\n', 'utf8');
        h.update(content, 'utf8');
        h.update('\n', 'utf8');
    }
    return h.digest('hex');
}

async function runTests() {
    log("\n🔒 INITIATING GHOST INTEGRITY PROTOCOL...\n", COLORS.cyan);

    let passed = 0;
    let failed = 0;

    async function test(name: string, fn: () => Promise<void>) {
        try {
            process.stdout.write(`TEST: ${name}... `);
            await fn();
            process.stdout.write(`${COLORS.green}PASSED${COLORS.reset}\n`);
            passed++;
        } catch (e) {
            process.stdout.write(`${COLORS.red}FAILED${COLORS.reset}\n`);
            process.stderr.write(`${String(e)}\n`);
            // Write error to file for debugging (opt-in only)
            if (process.env.GHOST_VERIFY_WRITE_LOG === 'true') {
                fs.writeFileSync('verification_error.log', JSON.stringify(e, Object.getOwnPropertyNames(e)) + '\n' + String(e));
            }
            failed++;
        }
    }

    // --- TEST SUITE 1: Deniable Encryption ---
    await test("Deniable Encryption (Dual Key Generation)", async () => {
        const realContent = "COORDINATES: 45.4215 N, 75.6972 W";
        const decoyContent = "Mom's Apple Pie Recipe: 2 cups flour...";

        const realPass = "swordfish_actual";
        const decoyPass = "love_my_mom_123";

        // 1. Encrypt
        log("\n   Generating Hidden Volume...", COLORS.yellow);
        const packedData = await DeniableEncryption.createHiddenVolume(
            realContent,
            decoyContent,
            decoyPass, // outer
            realPass   // inner
        );

        if (typeof packedData !== 'string' || packedData.length < 32) {
            throw new Error("Encryption output missing packed payload");
        }

        // 2. Decrypt with DECOY password
        const decoyResult = await DeniableEncryption.decryptHiddenVolume(packedData, decoyPass);
        if (!decoyResult || decoyResult.content !== decoyContent) {
            throw new Error(`Decoy decryption failed. Got: ${decoyResult?.content}`);
        }
        if (decoyResult.isDecoy !== true) {
            throw new Error("System failed to identify content as DECOY");
        }

        // 3. Decrypt with REAL password
        const realResult = await DeniableEncryption.decryptHiddenVolume(packedData, realPass);
        if (!realResult || realResult.content !== realContent) {
            throw new Error(`Real decryption failed. Got: ${realResult?.content}`);
        }
        if (realResult.isDecoy !== false) {
            throw new Error("System failed to identify content as REAL");
        }
    });

    // --- TEST SUITE 2: RAM-Only Persistence ---
    await test("Memory Queue (RAM-Only Compliance)", async () => {
        const queue = new ClientMessageQueue();
        const sessionId = "TEST-SESSION-001";

        // Add message
        queue.addMessage(sessionId, {
            id: "msg-1",
            content: "Burn after reading",
            sender: "me",
            timestamp: Date.now(),
            type: "text"
        });

        // Verify retrieval
        const messages = queue.getMessages(sessionId);
        if (messages.length !== 1 || messages[0].content !== "Burn after reading") {
            throw new Error("Message retrieval failed");
        }

        // NUCLEAR PURGE
        queue.nuclearPurge();

        // Verify destruction
        const postPurge = queue.getMessages(sessionId);
        if (postPurge.length !== 0) {
            throw new Error("Memory NOT cleared after nuclear purge");
        }

        if (!queue.isDestroyed()) {
            throw new Error("Queue not marked as destroyed");
        }
    });

    // --- SUMMARY ---
    process.stdout.write("\n-------------------------------------------\n");
    if (failed === 0) {
        const scriptDir = path.dirname(fileURLToPath(import.meta.url));
        const repoRoot = path.resolve(scriptDir, '..');
        const integrityHash = computeRepoIntegrityHash(repoRoot);
        log(`INTEGRITY_HASH_SHA256=${integrityHash}`, COLORS.cyan);
        log(`✅ INTEGRITY VERIFIED. SYSTEM GREEN. (${passed}/${passed})`, COLORS.green);
        process.exit(0);
    } else {
        log(`❌ INTEGRITY COMPROMISED. (${failed} FAULTS DETECTED)`, COLORS.red);
        process.exit(1);
    }
}

runTests();

