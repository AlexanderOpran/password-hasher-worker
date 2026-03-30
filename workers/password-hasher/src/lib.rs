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

/// Convert a [`HashError`] into a JS `Error` with a machine-readable code.
///
/// - `error.message` → human-readable description (from `Display`)
/// - `error.name`    → machine-readable error code (e.g. `VALIDATION_EMPTY_PASSWORD`)
///
/// `Error.name` is part of the standard Error interface and survives
/// Cloudflare service-binding RPC serialization (structured clone).
fn hash_error_to_js(e: &HashError) -> JsValue {
    let error = js_sys::Error::new(&e.to_string());
    error.set_name(e.code());
    error.into()
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
