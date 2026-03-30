/**
 * OWASP Password Storage Cheat Sheet — Compliance Test Suite
 *
 * All calls go through the **benchmark-proxy** worker which forwards them
 * to the password-hasher via Cloudflare service bindings (RPC).
 *
 * References:
 *   - OWASP Password Storage Cheat Sheet (2024)
 *   - RFC 9106 (Argon2)
 *   - PCI DSS v4.0 §8.3.2
 *
 * This suite validates that the worker implementation meets or exceeds
 * OWASP requirements with a financial-grade Argon2id configuration
 * (64 MiB, t=1, p=1, 256-bit output).
 *
 * Run: npx vitest run benchmark/src/compliance.test.ts
 */

import { describe, expect, it } from 'vitest';

import { HasherClient } from './client';
import { expectValidPHC, parsePHC } from './phc';

const BENCHMARK_PROXY_URL
  = process.env.BENCHMARK_PROXY_URL ?? 'http://localhost:8790';

const client = new HasherClient(BENCHMARK_PROXY_URL, 30_000);

// ═══════════════════════════════════════════════════════════════════
//   OWASP-01: Algorithm Selection
//   OWASP minimum: 19 MiB, t=2, p=1. OWASP preferred: 46 MiB, t=1, p=1.
//   We exceed both with a financial-grade configuration: 64 MiB, t=1, p=1
//   — maximizes memory cost within Cloudflare Workers' 128 MiB limit.
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-01–04: Algorithm, memory, time cost, parallelism', () => {
  it('algorithm is argon2id (not argon2i or argon2d)', async () => {
    const { hash } = await client.hash('owasp-01');
    const fields = parsePHC(hash);
    expect(fields.algorithm).toBe('argon2id');
  });

  it('all financial-grade parameters are met in a single hash', async () => {
    const { hash } = await client.hash('owasp-params');
    const fields = expectValidPHC(hash);
    // expectValidPHC asserts: argon2id, v=19, m≥65536, t≥1, p≥1,
    // salt≥128bits, output=256bits — this test pins the exact requirement.
    expect(fields.m).toBeGreaterThanOrEqual(64 * 1024);
    expect(fields.t).toBeGreaterThanOrEqual(1);
    expect(fields.p).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════
// OWASP-05: Salt Requirements
//   "Generate a salt using a CSPRNG"
//   "Salt should be at least 128 bits (16 bytes)"
//   "Salt must be unique per stored credential"
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-05: Salt requirements', () => {
  it('salt is present and ≥ 128 bits', async () => {
    const { hash } = await client.hash('owasp-05');
    const fields = parsePHC(hash);
    // 16 bytes = ceil(16*4/3) = 22 base64 chars (no padding in PHC)
    expect(fields.salt.length).toBeGreaterThanOrEqual(22);
  });

  it('salts are unique across 10 sequential hashes', async () => {
    const salts: string[] = [];
    for (let i = 0; i < 10; i++) {
      const { hash } = await client.hash('owasp-05-unique');
      salts.push(parsePHC(hash).salt);
    }
    expect(new Set(salts).size).toBe(10);
  });

  it('salts are unique across 5 parallel hashes', async () => {
    const results = await Promise.all(
      Array.from({ length: 5 }, () => client.hash('owasp-05-parallel')),
    );
    const salts = results.map((r) => parsePHC(r.hash).salt);
    expect(new Set(salts).size).toBe(5);
  });
});

// ═══════════════════════════════════════════════════════════════════
// OWASP-06: Output Length
//   Argon2id output should be at least 256 bits (32 bytes)
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-06–07: Output length and version', () => {
  it('output is 32 bytes (256 bits) and version is v=19', async () => {
    const { hash } = await client.hash('owasp-06-07');
    const fields = expectValidPHC(hash);
    expect(fields.hash.length).toBe(43); // 32 bytes → 43 base64
    expect(fields.version).toBe('v=19');
  });
});

// ═══════════════════════════════════════════════════════════════════
// OWASP-08: Unicode Normalization
//   "Where possible, use a library that handles Unicode normalization
//    for you, such as NFKC or equivalent."
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-08: Unicode NFKC normalization', () => {
  const normalizationPairs = [
    {
      name: 'Ångström → Latin A ring',
      input: '\u212B',
      normalized: '\u00C5',
    },
    {
      name: 'decomposed é → composed é',
      input: '\u0065\u0301',
      normalized: '\u00E9',
    },
    {
      name: 'fullwidth A → ASCII A',
      input: '\uFF21',
      normalized: 'A',
    },
    {
      name: 'superscript ² → digit 2',
      input: '\u00B2',
      normalized: '2',
    },
    {
      name: 'Roman Ⅲ → III',
      input: '\u2162',
      normalized: 'III',
    },
    {
      name: 'fi ligature → fi',
      input: '\uFB01',
      normalized: 'fi',
    },
  ];

  for (const { name, input, normalized } of normalizationPairs) {
    it(name, async () => {
      const { hash } = await client.hash(input);
      const { verified } = await client.verify(hash, normalized);
      expect(verified).toBe(true);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// OWASP-09: Password Length Limits
//   "Set a maximum length of at least 64 characters"
//   Must prevent DoS via extremely long passwords
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-09: Password length handling', () => {
  it('accepts 64-character password (OWASP minimum max)', async () => {
    const pw = 'A'.repeat(64);
    const { hash } = await client.hash(pw);
    const { verified } = await client.verify(hash, pw);
    expect(verified).toBe(true);
  });

  it('accepts 128-byte password (implementation max)', async () => {
    const pw = 'B'.repeat(128);
    const { hash } = await client.hash(pw);
    const { verified } = await client.verify(hash, pw);
    expect(verified).toBe(true);
  });

  it('rejects password > 128 bytes (DoS protection)', async () => {
    const res = await client.hashRaw('D'.repeat(129));
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it('rejects empty password', async () => {
    const res = await client.hashRaw('');
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ═══════════════════════════════════════════════════════════════════
// OWASP-10: Timing Attack Resistance
//   Verification of correct vs incorrect passwords should take
//   approximately the same time (constant-time comparison).
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-10: Timing attack resistance', () => {
  // NOTE: Measures end-to-end latency including network and RPC overhead,
  // not pure Argon2 computation. The ratio check is a coarse sanity check.
  it('correct and wrong password verify in similar time (< 3x ratio)', async () => {
    const { hash } = await client.hash('timing-attack-test');

    const correctMs: number[] = [];
    const wrongMs: number[] = [];

    for (let i = 0; i < 5; i++) {
      const c = await client.verify(hash, 'timing-attack-test');
      correctMs.push(c.latencyMs);
      const w = await client.verify(hash, 'wrong-timing-test');
      wrongMs.push(w.latencyMs);
    }

    const avgC = correctMs.reduce((a, b) => a + b) / correctMs.length;
    const avgW = wrongMs.reduce((a, b) => a + b) / wrongMs.length;
    const ratio = avgC > avgW ? avgC / avgW : avgW / avgC;

    expect(ratio).toBeLessThan(3.0);
  }, 60_000);
});

// ═══════════════════════════════════════════════════════════════════
// OWASP-11: Error Handling / Information Leakage
//   "Do not reveal which part of the credential failed"
//   No stack traces, no internal paths, no panic messages
// ═══════════════════════════════════════════════════════════════════

describe('OWASP-11: Error handling / no info leak', () => {
  it('empty password returns 4xx without stack traces', async () => {
    const res = await client.hashRaw('');
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    const lower = res.body.toLowerCase();
    expect(lower).not.toContain('stack');
    expect(lower).not.toContain('panic');
    expect(lower).not.toContain('unwrap');
  });

  it('malformed hash returns 4xx without internal details', async () => {
    const res = await client.verifyRaw('garbage', 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    const lower = res.body.toLowerCase();
    expect(lower).not.toContain('stack');
    expect(lower).not.toContain('file:');
    expect(lower).not.toContain('/src/');
  });
});

// ═══════════════════════════════════════════════════════════════════
// FINANCIAL-01: Computational Cost Validation
//   Hash should take meaningful compute time (>50ms even via RPC)
//   to prevent brute-force at scale.
// ═══════════════════════════════════════════════════════════════════

describe('FINANCIAL-01: Computational cost', () => {
  // NOTE: These measure end-to-end latency (network + RPC + Argon2 CPU time),
  // not pure computation time. They may be flaky on very fast local setups or
  // pass even with weak parameters on slow networks.
  it('hash takes > 50ms (brute-force resistance)', async () => {
    const { latencyMs } = await client.hash('financial-cost-test');
    expect(latencyMs).toBeGreaterThan(50);
  });

  it('verify takes > 50ms (brute-force resistance)', async () => {
    const { hash } = await client.hash('financial-cost-verify');
    const { latencyMs } = await client.verify(hash, 'financial-cost-verify');
    expect(latencyMs).toBeGreaterThan(50);
  });
});

// ═══════════════════════════════════════════════════════════════════
// FINANCIAL-02: Random Salt Uniqueness
//   Each hash operation must use a unique random salt, ensuring that
//   identical passwords produce distinct hashes (best practice).
// ═══════════════════════════════════════════════════════════════════

describe('FINANCIAL-02: Random salt ensures unique hashes', () => {
  it('same password hashed twice produces different hashes; both verify', async () => {
    const pw = 'random-salt-test';
    const { hash: h1 } = await client.hash(pw);
    const { hash: h2 } = await client.hash(pw);
    // Random salts must produce different hashes
    expect(h1).not.toBe(h2);
    // Both must verify correctly against the original password
    expect((await client.verify(h1, pw)).verified).toBe(true);
    expect((await client.verify(h2, pw)).verified).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════
// PCI-DSS-01: No Reversibility
//   The stored hash must not be reversible to the original password.
// ═══════════════════════════════════════════════════════════════════

describe('PCI-DSS-01: Irreversibility', () => {
  it('different passwords produce different hash outputs', async () => {
    const passwords = ['alpha', 'bravo', 'charlie', 'delta', 'echo'];
    const hashes = await Promise.all(passwords.map((p) => client.hash(p)));
    const outputs = hashes.map((h) => parsePHC(h.hash).hash);
    expect(new Set(outputs).size).toBe(passwords.length);
  });

  it('hash does not contain plaintext password', async () => {
    const pw = 'visiblepassword12345';
    const { hash } = await client.hash(pw);
    expect(hash).not.toContain(pw);
  });
});
