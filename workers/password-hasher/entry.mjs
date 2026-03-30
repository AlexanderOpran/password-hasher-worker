// Re-exports the worker-build output (WorkerEntrypoint with RPC methods).
// This worker is RPC-only (called via service binding).
import Hasher from "./build/index.js";

// Cloudflare requires a fetch handler even for RPC-only workers.
// Extend the generated entrypoint to add one.
class PasswordHasher extends Hasher {
  async fetch() {
    return new Response(null, { status: 404 });
  }
}

export default PasswordHasher;
