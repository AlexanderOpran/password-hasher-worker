/**
 * Benchmark proxy worker — benchmarks and tests the Argon2id password-hasher
 * worker via Cloudflare **service binding** (RPC), not public HTTP.
 *
 * The service binding is declared in wrangler.jsonc and injected via `env`.
 * The bound worker exposes `hashPassword(password)` and
 * `verifyPassword(hash, password)` as RPC methods on its entrypoint class.
 *
 * This worker exposes a simple HTTP API so that external tools (vitest,
 * tsx runner, curl) can drive benchmarks and tests without needing direct
 * access to the password-hasher worker.
 *
 * Routes:
 *   GET  /                → metadata
 *   POST /rpc/hash        → { hash }
 *   POST /rpc/verify      → { verified }
 */

import { WorkerEntrypoint } from 'cloudflare:workers';

/**
 * Typing for the RPC interface exposed by the password-hasher worker.
 */
interface HasherRpc {
  hashPassword(password: string): Promise<string>;
  verifyPassword(hash: string, password: string): Promise<boolean>;
}

interface Env {
  // WASM workers expose RPC methods but aren't a WorkerEntrypoint subclass,
  // so Service<T> can't express the constraint. Use Fetcher and cast at call site.
  PASSWORD_HASHER: Fetcher;
}

function auditLog(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
}

/**
 * Extracts structured error info from password-hasher RPC errors.
 *
 * The worker always formats `Error.message` as `"CODE: human message"`
 * (e.g. `"VALIDATION_EMPTY_PASSWORD: Password must not be empty."`).
 * This format is used because Cloudflare RPC does not preserve `Error.name`
 * (or custom properties) in production — only the message survives.
 */
interface RpcErrorExtract {
  code?: string;
  message: string;
}

const ERROR_CODE_SEPARATOR = ': ';
const ERROR_CODE_REGEX = /^[A-Z][A-Z_]+$/;

function extractRpcError(err: unknown): RpcErrorExtract {
  if (!(err instanceof Error)) {
    return { message: String(err) };
  }

  const separatorIndex = err.message.indexOf(ERROR_CODE_SEPARATOR);

  if (separatorIndex !== -1) {
    const potentialCode = err.message.slice(0, separatorIndex);

    if (ERROR_CODE_REGEX.test(potentialCode)) {
      return {
        code: potentialCode,
        message: err.message.slice(separatorIndex + ERROR_CODE_SEPARATOR.length),
      };
    }
  }

  return { message: err.message };
}

export default class BenchmarkProxy extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    const startMs = Date.now();
    const cfRay = request.headers.get('cf-ray') ?? 'local';
    const log = (action: string, status: number): void =>
      auditLog({ action, status, latencyMs: Date.now() - startMs, cfRay });

    const url = new URL(request.url);
    const path = url.pathname;
    const hasher = this.env.PASSWORD_HASHER as unknown as HasherRpc;

    // ── Metadata ──────────────────────────────────────────────
    if (request.method === 'GET' && path === '/') {
      log('metadata', 200);
      return Response.json({
        worker: 'benchmark-proxy',
        mode: 'service-binding-rpc',
        routes: [
          'POST /rpc/hash   { password }',
          'POST /rpc/verify  { hash, password }',
        ],
      });
    }

    // ── Parse /rpc/:action ────────────────────────────────────
    const rpcMatch = /^\/rpc\/(hash|verify)$/.exec(path);
    if (!rpcMatch || request.method !== 'POST') {
      log('not-found', 404);
      return Response.json({ error: 'Not Found' }, { status: 404 });
    }

    const [, action] = rpcMatch;

    // ── Input validation ──────────────────────────────────────
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      log('invalid-json', 400);
      return Response.json(
        { error: 'Invalid JSON body' },
        { status: 400 },
      );
    }

    if (typeof body !== 'object' || body === null) {
      log('invalid-body', 400);
      return Response.json(
        { error: 'Request body must be a JSON object' },
        { status: 400 },
      );
    }

    const fields = body as Record<string, unknown>;

    // ── Hash ─────────────────────────────────────────────────
    if (action === 'hash') {
      if (typeof fields.password !== 'string') {
        log('hash', 400);
        return Response.json(
          { error: 'Missing \'password\' field' },
          { status: 400 },
        );
      }
      try {
        const hash = await hasher.hashPassword(fields.password);
        log('hash', 200);
        return Response.json({ hash });
      } catch (err: unknown) {
        const { code, message } = extractRpcError(err);
        log('hash', 400);
        const body = code !== undefined ? { code, error: message } : { error: message };
        return Response.json(body, { status: 400 });
      }
    }

    // ── Verify ───────────────────────────────────────────────
    if (action === 'verify') {
      if (typeof fields.hash !== 'string') {
        log('verify', 400);
        return Response.json(
          { error: 'Missing \'hash\' field' },
          { status: 400 },
        );
      }
      if (typeof fields.password !== 'string') {
        log('verify', 400);
        return Response.json(
          { error: 'Missing \'password\' field' },
          { status: 400 },
        );
      }
      try {
        const verified = await hasher.verifyPassword(fields.hash, fields.password);
        log('verify', 200);
        return Response.json({ verified });
      } catch (err: unknown) {
        const { code, message } = extractRpcError(err);
        log('verify', 400);
        const body = code !== undefined ? { code, error: message } : { error: message };
        return Response.json(body, { status: 400 });
      }
    }

    log('not-found', 404);
    return Response.json({ error: 'Not Found' }, { status: 404 });
  }
}
