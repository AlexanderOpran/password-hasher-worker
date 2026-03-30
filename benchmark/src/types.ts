/**
 * Shared types for benchmark and test infrastructure.
 *
 * All communication with the password-hasher worker goes through the
 * benchmark-proxy worker via Cloudflare service bindings (RPC). The
 * benchmark-proxy exposes an HTTP API that proxies RPC calls to the
 * password-hasher worker.
 */

export interface HashResponse {
  hash: string;
}

export interface VerifyResponse {
  verified: boolean;
}

export interface ErrorResponse {
  code?: string;
  error: string;
}

export interface MetadataResponse {
  mode: string;
  worker: string;
}

export interface BenchmarkResult {
  concurrency: number;
  durationMs: number;
  errorBreakdown: Record<string, number>;
  failureCount: number;
  latencies: LatencyStats;
  preset: string;
  successCount: number;
  successRate: number;
  throughput: number;
  totalRequests: number;
  worker: string;
}

export interface LatencyStats {
  max: number;
  mean: number;
  median: number;
  min: number;
  p95: number;
  p99: number;
  stdDev: number;
}

export interface BenchmarkConfig {
  concurrencyLevels: number[];
  password: string;
  proxyUrl: string;
  requestsPerLevel: number;
  timeoutMs: number;
  warmupRequests: number;
}
