use std::fmt;

/// Errors produced by the password hashing and verification operations.
///
/// Each variant has a machine-readable code (via [`HashError::code`]) and a
/// human-readable description. The [`Display`] impl formats both as
/// `"CODE: human message"` — this is the canonical format transmitted via
/// `Error.message` across the Cloudflare service-binding RPC boundary.
#[derive(Debug)]
pub(crate) enum HashError {
    // ── Validation errors ─────────────────────────────────────
    EmptyPassword,
    PasswordTooLong(usize),
    NormalizedPasswordTooLong(usize),
    EmptyHash,
    HashTooLong(usize),
    InvalidHash(String),
    UnsupportedAlgorithm,

    // ── Cryptographic errors ──────────────────────────────────
    HashingFailed(String),
    VerificationFailed(String),
    RngFailed(String),
    SaltEncodingFailed(String),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.human_message())
    }
}

impl std::error::Error for HashError {}

impl HashError {
    /// Machine-readable error code for RPC consumers.
    ///
    /// Codes follow the pattern `{CATEGORY}_{SPECIFIC}`:
    ///   - `VALIDATION_*` — invalid input from the caller
    ///   - `CRYPTO_*`     — internal cryptographic operation failure
    ///
    /// Transmitted as a prefix in `Error.message` on the JS boundary
    /// (e.g. `"VALIDATION_EMPTY_PASSWORD: Password must not be empty."`).
    /// Cloudflare service-binding RPC does not preserve custom `Error.name`
    /// values in production (only built-in types like TypeError survive),
    /// so the code is embedded in the message instead.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyPassword => "VALIDATION_EMPTY_PASSWORD",
            Self::PasswordTooLong(_) => "VALIDATION_PASSWORD_TOO_LONG",
            Self::NormalizedPasswordTooLong(_) => "VALIDATION_NORMALIZED_TOO_LONG",
            Self::EmptyHash => "VALIDATION_EMPTY_HASH",
            Self::HashTooLong(_) => "VALIDATION_HASH_TOO_LONG",
            Self::InvalidHash(_) => "VALIDATION_INVALID_HASH",
            Self::UnsupportedAlgorithm => "VALIDATION_UNSUPPORTED_ALGORITHM",
            Self::HashingFailed(_) => "CRYPTO_HASH_FAILED",
            Self::VerificationFailed(_) => "CRYPTO_VERIFY_FAILED",
            Self::RngFailed(_) => "CRYPTO_RNG_FAILED",
            Self::SaltEncodingFailed(_) => "CRYPTO_SALT_ENCODING_FAILED",
        }
    }

    /// Human-readable error description (without the code prefix).
    fn human_message(&self) -> String {
        match self {
            Self::EmptyPassword => "Password must not be empty.".to_string(),
            Self::PasswordTooLong(n) => {
                format!("Password exceeds the maximum supported length of {n} bytes.")
            }
            Self::NormalizedPasswordTooLong(n) => {
                format!("Password exceeds the maximum supported length of {n} bytes after Unicode normalization (NFKC).")
            }
            Self::EmptyHash => "Hash must not be empty.".to_string(),
            Self::HashTooLong(n) => {
                format!("Hash exceeds the maximum supported length of {n} bytes.")
            }
            Self::InvalidHash(detail) => format!("Invalid Argon2id hash: {detail}"),
            Self::UnsupportedAlgorithm => "Only Argon2id hashes are accepted.".to_string(),
            Self::HashingFailed(detail) => format!("Argon2id hashing failed: {detail}"),
            Self::VerificationFailed(detail) => {
                format!("Argon2id verification failed: {detail}")
            }
            Self::RngFailed(detail) => format!("Failed to generate Argon2 salt: {detail}"),
            Self::SaltEncodingFailed(detail) => {
                format!("Failed to encode Argon2 salt: {detail}")
            }
        }
    }
}
