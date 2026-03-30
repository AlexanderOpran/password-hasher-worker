/**
 * Statistical utility functions for benchmark analysis.
 */

import type { BenchmarkResult, LatencyStats } from './types';

export function computeLatencyStats(latencies: number[]): LatencyStats {
  if (latencies.length === 0) {
    return { min: 0, max: 0, mean: 0, median: 0, p95: 0, p99: 0, stdDev: 0 };
  }

  const sorted = [...latencies].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / n;

  const variance
    = n > 1
      ? sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / (n - 1)
      : 0;
  const stdDev = Math.sqrt(variance);

  const median = n % 2 === 0
    ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    : sorted[Math.floor(n / 2)];

  return {
    min: sorted[0],
    max: sorted[n - 1],
    mean: Math.round(mean * 100) / 100,
    median: Math.round(median * 100) / 100,
    p95: sorted[Math.min(Math.ceil(n * 0.95) - 1, n - 1)],
    p99: sorted[Math.min(Math.ceil(n * 0.99) - 1, n - 1)],
    stdDev: Math.round(stdDev * 100) / 100,
  };
}

export function formatBenchmarkTable(results: BenchmarkResult[]): string {
  const header
    = '| Worker          | Concurrency | Success% | Mean(ms) | P95(ms) | P99(ms) | Throughput(req/s) |';
  const separator
    = '|-----------------|-------------|----------|----------|---------|---------|-------------------|';
  const rows = results.map(
    (r) =>
      `| ${r.worker.padEnd(15)} | ${String(r.concurrency).padEnd(11)} | ${(r.successRate * 100).toFixed(1).padStart(7)}% | ${String(r.latencies.mean).padStart(8)} | ${String(r.latencies.p95).padStart(7)} | ${String(r.latencies.p99).padStart(7)} | ${r.throughput.toFixed(1).padStart(17)} |`,
  );
  return [header, separator, ...rows].join('\n');
}
