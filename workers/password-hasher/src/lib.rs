mod error;
mod hash;

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::HashError;

// Argon2id Cloudflare Worker — exposes RPC methods via `wasm_bindgen`
// for use with Cloudflare service bindings. No HTTP routes are exposed;
// this worker is intended to be called exclusively via service binding
// from another worker (e.g. a better-auth worker).

/// Convert a [`HashError`] into a JS `Error` for the RPC boundary.
///
/// `Error.message` is set to `"CODE: human message"` (from `Display`),
/// e.g. `"VALIDATION_EMPTY_PASSWORD: Password must not be empty."`.
///
/// We intentionally do NOT set `Error.name` because Cloudflare RPC in
/// production only preserves prototype names of built-in error types
/// (TypeError, RangeError, etc.). Custom `.name` values on plain `Error`
/// instances get folded into `.message` as `"${name}: ${message}"`,
/// which would double-prefix the code. The message is the single
/// source of truth for error codes across the RPC boundary.
fn hash_error_to_js(e: &HashError) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}

/// RPC: hash a password with Argon2id. Called via service binding.
#[wasm_bindgen(js_name = hashPassword)]
#[allow(clippy::needless_pass_by_value)] // wasm_bindgen requires owned String
pub fn hash_password(password: String) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    hash::hash_password(&password).map_err(|ref e| hash_error_to_js(e))
}

/// RPC: verify a password against a stored Argon2id hash. Called via service binding.
#[wasm_bindgen(js_name = verifyPassword)]
#[allow(clippy::needless_pass_by_value)] // wasm_bindgen requires owned String
pub fn verify_password(hash: String, password: String) -> Result<bool, JsValue> {
    let hash = Zeroizing::new(hash);
    let password = Zeroizing::new(password);
    hash::verify_password(&hash, &password).map_err(|ref e| hash_error_to_js(e))
}
