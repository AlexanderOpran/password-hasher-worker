use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum HashError {
    // ── Validation errors ─────────────────────────────────────
    #[error("Password must not be empty.")]
    EmptyPassword,

    #[error("Password exceeds the maximum supported length of {0} bytes.")]
    PasswordTooLong(usize),

    #[error(
        "Password exceeds the maximum supported length of {0} bytes after Unicode normalization (NFKC)."
    )]
    NormalizedPasswordTooLong(usize),

    #[error("Hash must not be empty.")]
    EmptyHash,

    #[error("Hash exceeds the maximum supported length of {0} bytes.")]
    HashTooLong(usize),

    #[error("Invalid Argon2id hash: {0}")]
    InvalidHash(String),

    #[error("Only Argon2id hashes are accepted.")]
    UnsupportedAlgorithm,

    // ── Cryptographic errors ──────────────────────────────────
    #[error("Argon2id hashing failed: {0}")]
    HashingFailed(String),

    #[error("Argon2id verification failed: {0}")]
    VerificationFailed(String),

    #[error("Failed to generate Argon2 salt: {0}")]
    RngFailed(String),

    #[error("Failed to encode Argon2 salt: {0}")]
    SaltEncodingFailed(String),
}

impl HashError {
    /// Machine-readable error code for RPC consumers.
    ///
    /// Codes follow the pattern `{CATEGORY}_{SPECIFIC}`:
    ///   - `VALIDATION_*` — invalid input from the caller
    ///   - `CRYPTO_*`     — internal cryptographic operation failure
    ///
    /// Transmitted via `Error.name` on the JS boundary so it survives
    /// Cloudflare service-binding RPC serialization.
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
}
