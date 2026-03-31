# Password Hasher (Argon2id) Worker

Cloudflare Worker providing **Argon2id password hashing and verification** via Rust/WebAssembly, exposed through [service bindings (RPC)](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/) rather than public HTTP.

Designed as the hashing backend for [better-auth](https://www.better-auth.com/) on Cloudflare Workers.

## Key Properties

- **Argon2id** (RFC 9106 §4 recommended option: 64 MiB memory, 3 iterations, 1 lane, 32-byte output)
- **OWASP / NIST / PCI DSS** compliant, verified by an automated compliance test suite
- **NFKC Unicode normalization** on all passwords before hashing
- **Secure memory** with passwords zeroized after use via the `zeroize` crate
- **Constant-time verification** for timing-attack resistance
- **No public surface** with `workers_dev` disabled and direct HTTP requests returning `404`

## Architecture

```
                         service binding (RPC)
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────────┐
│  better-auth    │───→│  (caller worker) │───→│  password-hasher     │
│  or any worker  │    │                  │    │  Rust → WASM         │
└─────────────────┘    └──────────────────┘    │  hashPassword()      │
                                               │  verifyPassword()    │
                                               └──────────────────────┘
```

The password-hasher worker exposes two RPC methods via `wasm_bindgen`:

| Method | Signature | Returns |
|--------|-----------|---------|
| `hashPassword` | `(password: string)` | PHC-format hash string |
| `verifyPassword` | `(hash: string, password: string)` | `true` / throws on mismatch |

Direct HTTP requests return `404`. The worker is intended to be called exclusively via service binding RPC.

## Argon2id Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Memory | 64 MiB (65,536 KiB) | Maximizes cost within Cloudflare's 128 MiB worker limit |
| Time cost | 3 iterations | RFC 9106 §4 recommended for memory-constrained environments |
| Parallelism | 1 lane | Workers are single-threaded |
| Output | 32 bytes (256 bits) | Standard hash length |
| Salt | 16 bytes (128 bits) | Generated via `crypto.getRandomValues()` (BoringSSL CSPRNG) |

## Project Structure

```
password-hasher-worker/
├── workers/
│   ├── password-hasher/            # Core hasher (Rust to WASM)
│   │   ├── src/
│   │   │   ├── lib.rs              # wasm_bindgen RPC exports
│   │   │   ├── hash.rs             # Argon2id hashing logic + unit tests
│   │   │   └── error.rs            # HashError enum
│   │   ├── entry.mjs               # JS wrapper (404 for direct HTTP)
│   │   ├── wrangler.jsonc          # Worker config
│   │   └── Cargo.toml
│   │
│   └── benchmark-proxy/            # HTTP proxy for testing and benchmarks
│       ├── src/index.ts            # Routes HTTP to service binding RPC
│       └── wrangler.jsonc          # Service binding declaration
│
├── benchmark/                      # Test and benchmark infrastructure
│   └── src/
│       ├── integration.test.ts     # Correctness, special chars, stress tests
│       ├── compliance.test.ts      # OWASP/NIST/PCI compliance checks
│       ├── runner.ts               # CLI benchmark runner
│       ├── client.ts               # HTTP client for benchmark-proxy
│       ├── stats.ts                # Latency statistics and formatting
│       ├── phc.ts                  # PHC string parser and assertions
│       └── types.ts                # Shared types and presets
│
├── Cargo.toml                      # Rust workspace root
├── package.json                    # Scripts and JS dependencies
├── vitest.config.ts                # Test runner config
├── rust-toolchain.toml             # Rust stable + wasm32 target
└── eslint.config.js                # Linting rules
```

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (stable, with `wasm32-unknown-unknown` target; handled by `rust-toolchain.toml`)
- [Node.js](https://nodejs.org/) >= 18
- [Yarn](https://yarnpkg.com/) v4 (`corepack enable`)
- [`worker-build`](https://crates.io/crates/worker-build): `cargo install worker-build`

### Install

```bash
yarn install
```

### Development

Start both workers in separate terminals:

```bash
npm run dev          # password-hasher on :8788
npm run dev:bench    # benchmark-proxy on :8790 (service binding to hasher)
```

### Deploy

```bash
npx wrangler deploy --config workers/password-hasher/wrangler.jsonc
```

Then bind to it from your calling worker's `wrangler.jsonc`:

```jsonc
{
  "services": [
    { "binding": "PASSWORD_HASHER", "service": "password-hasher" }
  ]
}
```

## Testing

### Rust Unit Tests

```bash
npm run test:core       # cargo test -p password-hasher
```

Covers hashing roundtrips, PHC format, Unicode NFKC normalization, input validation, boundary conditions, timing characteristics, and interoperability.

### Integration Tests (via service bindings)

Requires both workers running (`npm run dev` + `npm run dev:bench`).

```bash
npm run test:integration    # Correctness, special chars, stress, concurrency
npm run test:compliance     # OWASP/NIST/PCI DSS compliance verification
npm run test:all            # All tests (cargo test + vitest)
```

**Environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCHMARK_PROXY_URL` | `http://localhost:8790` | URL of the benchmark-proxy worker |

## Benchmarking

All benchmarks use **Cloudflare service bindings** to measure the true production RPC path. This includes WASM instantiation, memory allocation, and Argon2 computation, but excludes public internet round-trips, DNS, TLS handshakes, and CDN routing.

```
┌──────────────────┐    HTTP     ┌──────────────────┐  service binding  ┌─────────────────────┐
│  vitest / tsx     │ ─────────→ │ benchmark-proxy   │ ───── RPC ──────→ │  password-hasher    │
│  (test driver)    │            │   (port 8790)     │                   │  (WorkerEntrypoint) │
└──────────────────┘            └──────────────────┘                   └─────────────────────┘
```

### Running Benchmarks

Requires both workers running.

```bash
npm run benchmark           # Concurrency 1,2,5,10 at 50 requests/level
npm run benchmark:full      # Concurrency 1,2,5,10,20 at 100 requests/level
```

### CLI Flags

```bash
tsx benchmark/src/runner.ts --concurrency 1,2,5,10,20 --requests 100 --bench-url http://localhost:8790
```

| Flag | Example | Description |
|------|---------|-------------|
| `--concurrency` | `1,2,5,10,20` | Comma-separated concurrency levels |
| `--requests` | `100` | Requests per concurrency level |
| `--bench-url` | `http://localhost:8790` | Benchmark-proxy URL override |

### Output

- **Console:** Per-level stats (success %, mean/p95/p99 latency, throughput) and summary table
- **JSON:** `benchmark/results/benchmark-rpc-<timestamp>.json`

### Why Service Bindings?

Service bindings are the **production deployment pattern** for this hasher. Benchmarking via public HTTP would measure network overhead that does not exist in production.

- **Zero network overhead** between caller and hasher
- **Direct RPC** with no HTTP parsing or JSON serialization on the hasher side
- **Accurate latency** measuring only WASM + Argon2 computation + RPC overhead
- **Production-identical** path, the same one a `better-auth` worker would use

## Sample Benchmark Results

Results from a full benchmark run (`npm run benchmark:full`) on the **Cloudflare Workers Pro plan**, measuring service binding RPC latency (100 requests per concurrency level, 100% success rate across all levels).

### Hash (Argon2id, 64 MiB)

| Concurrency | Mean | Median | P95 | P99 | Throughput |
|:-----------:|-----:|-------:|----:|----:|-----------:|
| 1 | 236 ms | 235 ms | 252 ms | 257 ms | 4.2 req/s |
| 2 | 243 ms | 239 ms | 254 ms | 337 ms | 8.1 req/s |
| 5 | 565 ms | 477 ms | 715 ms | 724 ms | 8.6 req/s |
| 10 | 1,100 ms | 1,135 ms | 1,197 ms | 1,353 ms | 8.6 req/s |
| 20 | 808 ms | 550 ms | 1,978 ms | 2,452 ms | 20.3 req/s |

### Verify

| Concurrency | Mean | Median | P95 | P99 | Throughput |
|:-----------:|-----:|-------:|----:|----:|-----------:|
| 1 | 242 ms | 241 ms | 259 ms | 264 ms | 4.1 req/s |
| 2 | 293 ms | 247 ms | 483 ms | 493 ms | 6.8 req/s |
| 5 | 571 ms | 576 ms | 703 ms | 723 ms | 8.6 req/s |
| 10 | 1,112 ms | 1,158 ms | 1,363 ms | 1,379 ms | 8.6 req/s |
| 20 | 565 ms | 512 ms | 1,221 ms | 1,445 ms | 30.6 req/s |

> **Key takeaway:** Single-request hash latency is ~236 ms. The platform maintains 100% success at all concurrency levels, with throughput plateauing around 8.6 req/s for concurrency 5–10 and bursting higher at concurrency 20 as the platform fans out requests across isolates.

## Scripts Reference

| Script | Description |
|--------|-------------|
| `npm run dev` | Dev password-hasher worker on `:8788` |
| `npm run dev:bench` | Dev benchmark-proxy on `:8790` |
| `npm run typecheck` | TypeScript type checking |
| `npm run lint` | ESLint check |
| `npm run lint:fix` | ESLint auto-fix |
| `npm run test:core` | Rust unit tests |
| `npm run test:integration` | Integration tests via service bindings |
| `npm run test:compliance` | OWASP/NIST/PCI compliance tests |
| `npm run test:all` | All tests (Rust + integration) |
| `npm run benchmark` | Default benchmark run |
| `npm run benchmark:full` | Full benchmark run |

## Tech Stack

| Layer | Technology |
|-------|------------|
| Hashing | Rust + `argon2` crate (Argon2id) |
| WASM | `wasm-bindgen`, `wasm32-unknown-unknown` target |
| Runtime | Cloudflare Workers |
| RPC | `@cloudflare/workers` service bindings |
| Tests | Vitest (integration), `cargo test` (unit) |
| Benchmarks | `tsx` CLI runner |
| Package manager | Yarn v4 |
