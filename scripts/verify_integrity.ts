
/**
 * GHOST INTEGRITY VERIFICATION SUITE
 * 
 * Purpose: comprehensive self-test of cryptographic claims.
 * Usage: npx tsx scripts/verify_integrity.ts
 */

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
            // Write error to file for debugging
            const fs = await import('fs');
            fs.writeFileSync('verification_error.log', JSON.stringify(e, Object.getOwnPropertyNames(e)) + '\n' + String(e));
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
        const hiddenVolume = await DeniableEncryption.createHiddenVolume(
            realContent,
            decoyContent,
            decoyPass, // outer
            realPass   // inner
        );

        if (!hiddenVolume.outerEncrypted || !hiddenVolume.innerEncrypted) {
            throw new Error("Encryption output missing fields");
        }

        // 2. Decrypt with DECOY password
        const decoyResult = await DeniableEncryption.decryptHiddenVolume(hiddenVolume, decoyPass);
        if (!decoyResult || decoyResult.content !== decoyContent) {
            throw new Error(`Decoy decryption failed. Got: ${decoyResult?.content}`);
        }
        if (decoyResult.isDecoy !== true) {
            throw new Error("System failed to identify content as DECOY");
        }

        // 3. Decrypt with REAL password
        const realResult = await DeniableEncryption.decryptHiddenVolume(hiddenVolume, realPass);
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
        log(`✅ INTEGRITY VERIFIED. SYSTEM GREEN. (${passed}/${passed})`, COLORS.green);
        process.exit(0);
    } else {
        log(`❌ INTEGRITY COMPROMISED. (${failed} FAULTS DETECTED)`, COLORS.red);
        process.exit(1);
    }
}

runTests();

