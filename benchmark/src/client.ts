/**
 * Client for interacting with the Argon2 password-hasher worker via the
 * benchmark-proxy service-binding proxy.
 *
 * All calls go through the benchmark-proxy worker, which forwards them to the
 * password-hasher worker via Cloudflare service bindings (RPC) — never via
 * public HTTP to the password-hasher worker directly.
 *
 * Routing:
 *   POST /rpc/hash    → hasher.hashPassword(password)
 *   POST /rpc/verify  → hasher.verifyPassword(hash, password)
 */

import type {
  ErrorResponse,
  HashResponse,
  MetadataResponse,
  VerifyResponse,
} from './types';

interface RawResponse {
  body: string;
  latencyMs: number;
  status: number;
}

/** Thrown when the hasher worker returns an error response. */
export class HasherError extends Error {
  /** Machine-readable error code (e.g. `VALIDATION_EMPTY_PASSWORD`), if available. */
  readonly code: string | undefined;

  constructor(code: string | undefined, message: string) {
    super(message);
    this.name = 'HasherError';
    this.code = code;
  }
}

function isHashResponse(data: unknown): data is HashResponse {
  return (
    typeof data === 'object'
    && data !== null
    && 'hash' in data
    && typeof (data as Record<string, unknown>).hash === 'string'
  );
}

function isVerifyResponse(data: unknown): data is VerifyResponse {
  return (
    typeof data === 'object'
    && data !== null
    && 'verified' in data
    && typeof (data as Record<string, unknown>).verified === 'boolean'
  );
}

function throwIfError(status: number, body: string): void {
  if (status >= 200 && status < 300) return;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new HasherError(undefined, `HTTP ${String(status)}: ${body}`);
  }
  if (
    typeof parsed === 'object'
    && parsed !== null
    && 'error' in parsed
  ) {
    const errBody = parsed as ErrorResponse;
    throw new HasherError(errBody.code, errBody.error);
  }
  throw new HasherError(undefined, `HTTP ${String(status)}: ${body}`);
}

export class HasherClient {
  private readonly proxyUrl: string;
  private readonly timeoutMs: number;

  constructor(proxyUrl: string, timeoutMs = 30_000) {
    this.proxyUrl = proxyUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  async metadata(): Promise<MetadataResponse> {
    const res = await this.request('GET', '/');
    return res.json() as Promise<MetadataResponse>;
  }

  async hash(password: string): Promise<{ hash: string; latencyMs: number }> {
    const { status, body, latencyMs } = await this.hashRaw(password);
    throwIfError(status, body);
    const data: unknown = JSON.parse(body);
    if (!isHashResponse(data)) {
      throw new HasherError(undefined, `Unexpected hash response: ${body.slice(0, 200)}`);
    }
    return { hash: data.hash, latencyMs };
  }

  async verify(
    hash: string,
    password: string,
  ): Promise<{ latencyMs: number; verified: boolean }> {
    const { status, body, latencyMs } = await this.verifyRaw(hash, password);
    throwIfError(status, body);
    const data: unknown = JSON.parse(body);
    if (!isVerifyResponse(data)) {
      throw new HasherError(undefined, `Unexpected verify response: ${body.slice(0, 200)}`);
    }
    return { verified: data.verified, latencyMs };
  }

  async hashRaw(password: string): Promise<RawResponse> {
    return this.timedRequest('POST', '/rpc/hash', { password });
  }

  async verifyRaw(hash: string, password: string): Promise<RawResponse> {
    return this.timedRequest('POST', '/rpc/verify', { hash, password });
  }

  private async timedRequest(
    method: string,
    path: string,
    body: unknown,
  ): Promise<RawResponse> {
    const start = performance.now();
    const res = await this.request(method, path, body);
    const latencyMs = performance.now() - start;
    return { status: res.status, body: await res.text(), latencyMs };
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await globalThis.fetch(`${this.proxyUrl}${path}`, {
        method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}
