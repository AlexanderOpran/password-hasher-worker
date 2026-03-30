/**
 * PHC (Password Hashing Competition) string parser and assertion helpers.
 *
 * PHC format: $argon2id$v=19$m=65536,t=1,p=1$<salt>$<hash>
 *             [0]    [1]  [2]     [3]       [4]    [5]
 *
 * Shared across integration and compliance test suites to keep
 * PHC-related assertions consistent and DRY.
 */

import { expect } from 'vitest';

export interface PHCFields {
  algorithm: string;
  hash: string;
  m: number;
  p: number;
  params: string;
  salt: string;
  t: number;
  version: string;
}

/** Parse a PHC string into its component fields. Throws on malformed input. */
export function parsePHC(phc: string): PHCFields {
  const parts = phc.split('$');
  if (parts.length !== 6) {
    throw new Error(
      `Expected 6 PHC fields, got ${String(parts.length)}: ${phc.slice(0, 80)}`,
    );
  }

  const paramMatch = /m=(\d+),t=(\d+),p=(\d+)/.exec(parts[3]);
  if (!paramMatch) {
    throw new Error(`Cannot parse PHC params: ${parts[3]}`);
  }

  return {
    algorithm: parts[1],
    version: parts[2],
    params: parts[3],
    m: Number(paramMatch[1]),
    t: Number(paramMatch[2]),
    p: Number(paramMatch[3]),
    salt: parts[4],
    hash: parts[5],
  };
}

/**
 * Assert that a hash string is a valid Argon2id PHC string meeting
 * financial-grade requirements (exceeds OWASP preferred):
 *   - Algorithm: argon2id
 *   - Version: v=19 (0x13)
 *   - Memory: ≥ 64 MiB (65536 KiB)
 *   - Iterations: ≥ 1
 *   - Parallelism: ≥ 1
 *   - Salt: ≥ 128 bits (≥ 22 base64 chars)
 *   - Output: 256 bits (43 base64 chars / 32 bytes)
 */
export function expectValidPHC(phc: string): PHCFields {
  const fields = parsePHC(phc);

  expect(fields.algorithm).toBe('argon2id');
  expect(fields.version).toBe('v=19');
  expect(fields.m).toBeGreaterThanOrEqual(64 * 1024);
  expect(fields.t).toBeGreaterThanOrEqual(1);
  expect(fields.p).toBeGreaterThanOrEqual(1);
  expect(fields.salt.length).toBeGreaterThanOrEqual(22);
  expect(fields.hash.length).toBe(43);

  return fields;
}
