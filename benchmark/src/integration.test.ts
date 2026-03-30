/**
 * Comprehensive integration tests for the Argon2id password-hasher worker.
 *
 * All calls go through the **benchmark-proxy** worker which forwards them
 * to the password-hasher via Cloudflare service bindings (RPC).
 *
 * Set environment variable to configure the benchmark-proxy URL:
 *   BENCHMARK_PROXY_URL=http://localhost:8790
 *
 * Run:  npx vitest run benchmark/src/integration.test.ts
 */

import { describe, expect, it } from 'vitest';

import { HasherClient, HasherError } from './client';
import { parsePHC } from './phc';

import type { ErrorResponse } from './types';

// ── Configuration ───────────────────────────────────────────────────

const BENCHMARK_PROXY_URL
  = process.env.BENCHMARK_PROXY_URL ?? 'http://localhost:8790';

const client = new HasherClient(BENCHMARK_PROXY_URL, 30_000);

/** Parse the JSON error body from a raw response. */
function parseError(body: string): ErrorResponse {
  return JSON.parse(body) as ErrorResponse;
}

describe('Connectivity', () => {
  it('benchmark-proxy responds with metadata', async () => {
    const meta = await client.metadata();
    expect(meta.worker).toBe('benchmark-proxy');
    expect(meta.mode).toBe('service-binding-rpc');
  });
});

// ═══════════════════════════════════════════════════════════════
// 1. BASIC CORRECTNESS
// ═══════════════════════════════════════════════════════════════

describe('Basic Correctness', () => {
  it('hash → verify roundtrip succeeds', async () => {
    const { hash } = await client.hash('correct horse battery staple');
    expect(hash).toMatch(/^\$argon2id\$/);
    const { verified } = await client.verify(
      hash,
      'correct horse battery staple',
    );
    expect(verified).toBe(true);
  });

  it('rejects wrong password', async () => {
    const { hash } = await client.hash('correct horse battery staple');
    const { verified } = await client.verify(hash, 'wrong password');
    expect(verified).toBe(false);
  });

  it('each hash call produces unique output (random salt)', async () => {
    const h1 = await client.hash('same-password');
    const h2 = await client.hash('same-password');
    expect(h1.hash).not.toBe(h2.hash);
  });

  it('is case-sensitive', async () => {
    const { hash } = await client.hash('Password123');
    const lower = await client.verify(hash, 'password123');
    const upper = await client.verify(hash, 'PASSWORD123');
    const exact = await client.verify(hash, 'Password123');
    expect(lower.verified).toBe(false);
    expect(upper.verified).toBe(false);
    expect(exact.verified).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// 2. PHC STRING FORMAT (RFC 9106)
// ═══════════════════════════════════════════════════════════════

describe('PHC String Format', () => {
  it('uses exact expected parameters (m=65536, t=1, p=1)', async () => {
    const { hash } = await client.hash('phc-format-test');
    const fields = parsePHC(hash);
    expect(fields.algorithm).toBe('argon2id');
    expect(fields.m).toBe(65536);
    expect(fields.t).toBe(1);
    expect(fields.p).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════
// 3. SPECIAL CHARACTER HANDLING
//    (NFKC normalization covered by owasp-compliance.test.ts)
// ═══════════════════════════════════════════════════════════════

describe('Special Characters', () => {
  const specialPasswords = [
    { name: 'emoji', password: '🔑🏦💰🔐' },
    { name: 'mixed scripts', password: 'Pässwörd密码パスワード' },
    { name: 'RTL Arabic', password: 'كلمة السر' },
    { name: 'whitespace-only', password: '   \t\n  ' },
    { name: 'null bytes', password: 'before\0after' },
    { name: 'max-length', password: 'a'.repeat(128) },
    { name: 'newlines', password: 'line1\nline2\rline3\r\nline4' },
  ];

  for (const { name, password } of specialPasswords) {
    it(`handles ${name}`, async () => {
      const { hash } = await client.hash(password);
      const { verified } = await client.verify(hash, password);
      expect(verified).toBe(true);
    });
  }
});

// ═══════════════════════════════════════════════════════════════
// 4. INPUT VALIDATION (Error handling via service binding)
//    (Detailed OWASP/length/info-leak checks in owasp-compliance.test.ts)
// ═══════════════════════════════════════════════════════════════

describe('Input Validation', () => {
  it('rejects empty password on hash', async () => {
    const res = await client.hashRaw('');
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it('rejects oversized password on hash (>128 bytes)', async () => {
    const res = await client.hashRaw('a'.repeat(129));
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it('rejects malformed hash on verify', async () => {
    const res = await client.verifyRaw('not-a-valid-hash', 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ═══════════════════════════════════════════════════════════════
// 5. RPC ERROR CODES
//    Validates that every triggerable validation error returns
//    the correct machine-readable `code` field alongside a
//    human-readable `error` message.
// ═══════════════════════════════════════════════════════════════

describe('RPC Error Codes', () => {
  // ── Hash errors ──────────────────────────────────────────

  it('empty password → VALIDATION_EMPTY_PASSWORD', async () => {
    const res = await client.hashRaw('');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_EMPTY_PASSWORD');
    expect(err.error).toBeTruthy();
  });

  it('oversized password → VALIDATION_PASSWORD_TOO_LONG', async () => {
    const res = await client.hashRaw('a'.repeat(129));
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_PASSWORD_TOO_LONG');
    expect(err.error).toContain('128');
  });

  it('NFKC-expanded password → VALIDATION_NORMALIZED_TOO_LONG', async () => {
    // U+3300 (㌀ SQUARE APAATO) is 3 UTF-8 bytes but NFKC-expands to
    // アパート (12 bytes). 42 copies = 126 bytes raw, 504 bytes normalized.
    const res = await client.hashRaw('\u3300'.repeat(42));
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_NORMALIZED_TOO_LONG');
    expect(err.error).toContain('normalization');
  });

  // ── Verify errors ────────────────────────────────────────

  it('empty password on verify → VALIDATION_EMPTY_PASSWORD', async () => {
    const res = await client.verifyRaw('$argon2id$v=19$m=65536,t=1,p=1$salt$hash', '');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_EMPTY_PASSWORD');
  });

  it('malformed hash → VALIDATION_INVALID_HASH', async () => {
    const res = await client.verifyRaw('not-a-valid-hash', 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_INVALID_HASH');
  });

  it('empty hash → VALIDATION_EMPTY_HASH', async () => {
    const res = await client.verifyRaw('', 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_EMPTY_HASH');
  });

  it('oversized hash → VALIDATION_HASH_TOO_LONG', async () => {
    const res = await client.verifyRaw('a'.repeat(4097), 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_HASH_TOO_LONG');
  });

  it('argon2i hash → VALIDATION_UNSUPPORTED_ALGORITHM', async () => {
    // Valid PHC format but wrong algorithm (argon2i instead of argon2id)
    const argon2iHash
      = '$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$KnPkRpJMfRMGcOkaw9MxOYbJM/VHoHJlkLeYN0zVtF4';
    const res = await client.verifyRaw(argon2iHash, 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_UNSUPPORTED_ALGORITHM');
  });

  it('argon2d hash → VALIDATION_UNSUPPORTED_ALGORITHM', async () => {
    const argon2dHash
      = '$argon2d$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$KnPkRpJMfRMGcOkaw9MxOYbJM/VHoHJlkLeYN0zVtF4';
    const res = await client.verifyRaw(argon2dHash, 'password');
    expect(res.status).toBeGreaterThanOrEqual(400);
    const err = parseError(res.body);
    expect(err.code).toBe('VALIDATION_UNSUPPORTED_ALGORITHM');
  });

  // ── Error structure ──────────────────────────────────────

  it('all error responses include both code and human-readable message', async () => {
    const scenarios = [
      { label: 'empty-pw hash', raw: client.hashRaw('') },
      { label: 'long-pw hash', raw: client.hashRaw('x'.repeat(129)) },
      { label: 'bad-hash verify', raw: client.verifyRaw('garbage', 'pw') },
    ];

    for (const { label, raw } of scenarios) {
      const res = await raw;
      const err = parseError(res.body);
      expect(err.code, `${label}: code must be present`).toBeTruthy();
      expect(err.code, `${label}: code must be SCREAMING_SNAKE`).toMatch(
        /^[A-Z]+_[A-Z_]+$/,
      );
      expect(err.error, `${label}: message must be present`).toBeTruthy();
      expect(typeof err.error, `${label}: message must be string`).toBe(
        'string',
      );
    }
  });

  // ── Client-side HasherError integration ──────────────────

  it('HasherError.code is populated when using high-level client methods', async () => {
    try {
      await client.hash('');
      expect.unreachable('should have thrown');
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(HasherError);
      const hasherErr = err as HasherError;
      expect(hasherErr.code).toBe('VALIDATION_EMPTY_PASSWORD');
      expect(hasherErr.message).toBeTruthy();
    }
  });

  it('HasherError.code is populated for verify errors', async () => {
    try {
      await client.verify('not-a-hash', 'password');
      expect.unreachable('should have thrown');
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(HasherError);
      const hasherErr = err as HasherError;
      expect(hasherErr.code).toBe('VALIDATION_INVALID_HASH');
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// 6. STRESS & CONCURRENCY
// ═══════════════════════════════════════════════════════════════

describe('Stress', () => {
  it('sequential stress test (20 hash+verify cycles)', async () => {
    for (let i = 0; i < 20; i++) {
      const pw = `stress-test-${i}-${Date.now()}`;
      const { hash } = await client.hash(pw);
      const { verified } = await client.verify(hash, pw);
      expect(verified).toBe(true);
    }
  }, 120_000);
});

describe('Concurrency', () => {
  it('handles 5 concurrent hash requests', async () => {
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, (_, i) =>
        client.hash(`concurrent-${i}`),
      ),
    );
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThanOrEqual(3);
  }, 60_000);

  it('handles 5 concurrent verify requests', async () => {
    const { hash } = await client.hash('concurrent-verify');
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, () =>
        client.verify(hash, 'concurrent-verify'),
      ),
    );
    const fulfilled = results.filter(
      (r) => r.status === 'fulfilled',
    ) as PromiseFulfilledResult<{ latencyMs: number; verified: boolean }>[];
    expect(fulfilled.length).toBeGreaterThanOrEqual(3);
    for (const r of fulfilled) {
      expect(r.value.verified).toBe(true);
    }
  }, 60_000);

  it('mixed hash+verify concurrent requests', async () => {
    const { hash } = await client.hash('mixed-test');
    const tasks = [
      client.hash('mixed-1'),
      client.hash('mixed-2'),
      client.verify(hash, 'mixed-test'),
      client.hash('mixed-3'),
      client.verify(hash, 'mixed-test'),
    ];
    const results = await Promise.allSettled(tasks);
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThanOrEqual(3);
  }, 60_000);
});
