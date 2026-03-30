/**
 * Benchmark runner — drives concurrent hash/verify requests against the
 * password-hasher worker via the **benchmark-proxy** service-binding proxy
 * (not public HTTP).
 *
 * All traffic flows:  runner → benchmark-proxy worker → (service binding RPC) → password-hasher worker
 *
 * Usage:
 *   npx tsx benchmark/src/runner.ts [--concurrency 1,2,5,10] [--requests 50] [--bench-url URL]
 *
 * Requires the benchmark-proxy worker to be running (locally via `wrangler dev` or deployed),
 * with service bindings configured to the password-hasher worker.
 */

import { HasherClient } from './client';
import { computeLatencyStats, formatBenchmarkTable } from './stats';

import type { BenchmarkConfig, BenchmarkResult } from './types';

// ── Default configuration ───────────────────────────────────────────

const BENCHMARK_PROXY_URL
  = process.env.BENCHMARK_PROXY_URL ?? 'http://localhost:8790';

const DEFAULT_CONFIG: BenchmarkConfig = {
  concurrencyLevels: [1, 2, 5, 10],
  requestsPerLevel: 50,
  warmupRequests: 3,
  password: 'bench-correct-horse-battery-staple',
  timeoutMs: 30_000,
  proxyUrl: BENCHMARK_PROXY_URL,
};

// ── Core benchmark logic ────────────────────────────────────────────

async function warmup(client: HasherClient, count: number): Promise<void> {
  console.log(`  Warming up with ${String(count)} requests...`);
  for (let i = 0; i < count; i++) {
    try {
      await client.hash('warmup');
    } catch {
      // Swallow warmup errors — cold start may fail
    }
  }
}

interface RequestOutcome {
  error?: string;
  latencyMs: number;
  ok: boolean;
}

async function runConcurrentBatch(
  task: () => Promise<{ latencyMs: number }>,
  count: number,
  concurrency: number,
): Promise<RequestOutcome[]> {
  const results: RequestOutcome[] = [];
  const inflight = new Set<Promise<void>>();

  for (let i = 0; i < count; i++) {
    const p = (async (): Promise<void> => {
      try {
        const { latencyMs } = await task();
        results.push({ ok: true, latencyMs });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        results.push({ ok: false, latencyMs: 0, error: message });
      }
    })();

    inflight.add(p);
    void p.finally(() => inflight.delete(p));

    if (inflight.size >= concurrency) {
      await Promise.race(inflight);
    }
  }

  await Promise.all(inflight);
  return results;
}

function analyzeResults(
  worker: string,
  preset: string,
  concurrency: number,
  outcomes: RequestOutcome[],
  durationMs: number,
): BenchmarkResult {
  const successes = outcomes.filter((o) => o.ok);
  const failures = outcomes.filter((o) => !o.ok);
  const errorBreakdown: Record<string, number> = {};
  for (const f of failures) {
    const key = f.error?.slice(0, 80) ?? 'unknown';
    errorBreakdown[key] = (errorBreakdown[key] ?? 0) + 1;
  }
  const latencies = computeLatencyStats(successes.map((o) => o.latencyMs));

  return {
    worker,
    preset,
    concurrency,
    totalRequests: outcomes.length,
    successCount: successes.length,
    failureCount: failures.length,
    errorBreakdown,
    successRate: outcomes.length > 0 ? successes.length / outcomes.length : 0,
    latencies,
    throughput:
      durationMs > 0 ? (successes.length / durationMs) * 1000 : 0,
    durationMs,
  };
}

// ── Main entry point ────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = { ...DEFAULT_CONFIG };

  // Parse CLI flags
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--concurrency' && args[i + 1]) {
      config.concurrencyLevels = args[++i].split(',').map(Number);
    }
    if (args[i] === '--requests' && args[i + 1]) {
      config.requestsPerLevel = Number(args[++i]);
    }
    if (args[i] === '--bench-url' && args[i + 1]) {
      config.proxyUrl = args[++i];
    }
  }

  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  Argon2id Worker Benchmark — Service Binding (RPC) Mode    ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log();
  console.log(`Benchmark-proxy: ${config.proxyUrl}`);
  console.log(`Concurrency:  ${config.concurrencyLevels.join(', ')}`);
  console.log(`Requests/lvl: ${String(config.requestsPerLevel)}`);
  console.log(`Warmup:       ${String(config.warmupRequests)}`);
  console.log();

  const client = new HasherClient(config.proxyUrl, config.timeoutMs);

  // Connectivity check (to the benchmark-proxy)
  try {
    const meta = await client.metadata();
    console.log(`✓ benchmark-proxy reachable — mode: ${meta.mode}`);
  } catch (err: unknown) {
    console.error(`✗ benchmark-proxy unreachable at ${config.proxyUrl}: ${String(err)}`);
    process.exit(1);
  }

  await warmup(client, config.warmupRequests);

  // Get a hash for verify benchmarks
  let referenceHash: string;
  try {
    const { hash } = await client.hash(config.password);
    referenceHash = hash;
  } catch (err: unknown) {
    console.error(`✗ Failed to get reference hash: ${String(err)}`);
    process.exit(1);
  }

  const allResults: BenchmarkResult[] = [];

  for (const concurrency of config.concurrencyLevels) {
    console.log(
      `\n─── password-hasher (RPC) | concurrency=${String(concurrency)} | ${String(config.requestsPerLevel)} requests ───`,
    );

    // Hash benchmark
    const hashStart = performance.now();
    const hashOutcomes = await runConcurrentBatch(
      () => client.hash(config.password),
      config.requestsPerLevel,
      concurrency,
    );
    const hashDuration = performance.now() - hashStart;
    const hashResult = analyzeResults(
      'password-hasher',
      'hash',
      concurrency,
      hashOutcomes,
      hashDuration,
    );
    allResults.push(hashResult);
    console.log(
      `  HASH:   ${String(hashResult.successRate * 100)}% success, `
      + `mean=${String(hashResult.latencies.mean)}ms, p95=${String(hashResult.latencies.p95)}ms, `
      + `throughput=${hashResult.throughput.toFixed(1)} req/s`,
    );

    // Verify benchmark
    const verifyStart = performance.now();
    const verifyOutcomes = await runConcurrentBatch(
      () => client.verify(referenceHash, config.password),
      config.requestsPerLevel,
      concurrency,
    );
    const verifyDuration = performance.now() - verifyStart;
    const verifyResult = analyzeResults(
      'password-hasher',
      'verify',
      concurrency,
      verifyOutcomes,
      verifyDuration,
    );
    allResults.push(verifyResult);
    console.log(
      `  VERIFY: ${String(verifyResult.successRate * 100)}% success, `
      + `mean=${String(verifyResult.latencies.mean)}ms, p95=${String(verifyResult.latencies.p95)}ms, `
      + `throughput=${verifyResult.throughput.toFixed(1)} req/s`,
    );

    // Error details
    for (const r of [hashResult, verifyResult]) {
      if (r.failureCount > 0) {
        console.log(`  Errors (${r.preset}):`);
        for (const [msg, count] of Object.entries(r.errorBreakdown)) {
          console.log(`    ${String(count)}x ${msg}`);
        }
      }
    }
  }

  // ── Summary table ─────────────────────────────────────────────
  console.log('\n\n════════════════════════ SUMMARY ════════════════════════\n');
  console.log('Mode: Service Binding (RPC) — no public HTTP\n');
  console.log('HASH operations:');
  console.log(
    formatBenchmarkTable(allResults.filter((r) => r.preset === 'hash')),
  );
  console.log('\nVERIFY operations:');
  console.log(
    formatBenchmarkTable(allResults.filter((r) => r.preset === 'verify')),
  );

  // ── JSON output ───────────────────────────────────────────────
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const nodeUrl = await import('node:url');
  const nodePath = await import('node:path');
  const outDir = nodePath.join(nodePath.dirname(nodeUrl.fileURLToPath(import.meta.url)), '..', 'results');
  const outFile = `${outDir}/benchmark-rpc-${timestamp}.json`;
  const fs = await import('node:fs');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(allResults, null, 2));
  console.log(`\nResults saved to ${outFile}`);
}

main().catch((err: unknown) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
