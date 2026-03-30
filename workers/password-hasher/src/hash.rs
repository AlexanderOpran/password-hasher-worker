use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::HashError;

/// Argon2id parameters — financial-grade configuration.
/// 64 MiB memory, 1 iteration, 1 lane, 32-byte output.
/// Maximises memory cost to make GPU/ASIC attacks prohibitively expensive
/// while fitting within Cloudflare Workers paid tier (128 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_TIME_COST: u32 = 1;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_OUTPUT_LEN: usize = 32;

const SALT_LEN: usize = 16;
const MAX_PASSWORD_LENGTH: usize = 128;
const MAX_HASH_LENGTH: usize = 4096;

fn normalize_password(password: &str) -> String {
    password.nfkc().collect()
}

fn validate_password(password: &str) -> Result<(), HashError> {
    if password.is_empty() {
        return Err(HashError::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(HashError::PasswordTooLong(MAX_PASSWORD_LENGTH));
    }
    Ok(())
}

fn validate_normalized_password(password: &str) -> Result<(), HashError> {
    if password.is_empty() {
        return Err(HashError::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(HashError::NormalizedPasswordTooLong(MAX_PASSWORD_LENGTH));
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), HashError> {
    if hash.is_empty() {
        return Err(HashError::EmptyHash);
    }
    if hash.len() > MAX_HASH_LENGTH {
        return Err(HashError::HashTooLong(MAX_HASH_LENGTH));
    }
    Ok(())
}

static ARGON2: LazyLock<Argon2<'static>> = LazyLock::new(|| {
    let params = Argon2Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .expect("BUG: hardcoded Argon2id parameters are invalid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
});

/// Hash a password with a random 16-byte salt.
pub fn hash_password(password: &str) -> Result<String, HashError> {
    validate_password(password)?;
    let normalized = Zeroizing::new(normalize_password(password));
    validate_normalized_password(&normalized)?;
    let mut salt_bytes = [0u8; SALT_LEN];
    // `wasm_js` delegates to `crypto.getRandomValues()` — on Cloudflare Workers
    // this is backed by BoringSSL's CSPRNG, not the V8 implementation.
    // See: https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
    getrandom::fill(&mut salt_bytes).map_err(|e| HashError::RngFailed(e.to_string()))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| HashError::SaltEncodingFailed(e.to_string()))?;
    salt_bytes.zeroize();
    let hash = ARGON2
        .hash_password(normalized.as_bytes(), &salt)
        .map_err(|e| HashError::HashingFailed(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2id PHC hash string.
pub fn verify_password(hash: &str, password: &str) -> Result<bool, HashError> {
    validate_password(password)?;
    validate_hash(hash)?;
    let normalized = Zeroizing::new(normalize_password(password));
    validate_normalized_password(&normalized)?;
    let parsed = PasswordHash::new(hash).map_err(|e| HashError::InvalidHash(e.to_string()))?;
    if parsed.algorithm != argon2::ARGON2ID_IDENT {
        return Err(HashError::UnsupportedAlgorithm);
    }
    match ARGON2.verify_password(normalized.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(HashError::VerificationFailed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::Instant;

    // ───────────────────────────────────────────────────────────
    // 1. BASIC CORRECTNESS
    // ───────────────────────────────────────────────────────────

    #[test]
    fn hash_and_verify_roundtrip() {
        let pw = "correct horse battery staple";
        let hash = hash_password(pw).expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(&hash, pw).expect("verify"));
    }

    #[test]
    fn wrong_password_rejected() {
        let hash = hash_password("correct horse battery staple").expect("hash");
        assert!(!verify_password(&hash, "wrong password").expect("verify"));
    }

    #[test]
    fn random_salt_uniqueness() {
        let mut hashes = HashSet::new();
        for _ in 0..10 {
            let h = hash_password("same-password").expect("hash");
            assert!(hashes.insert(h), "Random salt must make each hash unique");
        }
    }

    // ───────────────────────────────────────────────────────────
    // 2. PHC STRING FORMAT COMPLIANCE (RFC 9106)
    // ───────────────────────────────────────────────────────────

    #[test]
    fn phc_string_format_fields() {
        let hash = hash_password("test").expect("hash");
        let parsed = PasswordHash::new(&hash).expect("parse PHC");
        assert_eq!(parsed.algorithm, argon2::ARGON2ID_IDENT, "Must be argon2id");
        assert_eq!(
            parsed.version,
            Some(0x13),
            "Version must be 0x13 (19 decimal)"
        );
        let params = parsed.params;
        assert_eq!(
            params.get_str("m").map(|v| v.parse::<u32>().ok()),
            Some(Some(ARGON2_MEMORY_KIB)),
            "Memory parameter must match"
        );
        assert_eq!(
            params.get_str("t").map(|v| v.parse::<u32>().ok()),
            Some(Some(ARGON2_TIME_COST)),
            "Time cost parameter must match"
        );
        assert_eq!(
            params.get_str("p").map(|v| v.parse::<u32>().ok()),
            Some(Some(ARGON2_PARALLELISM)),
            "Parallelism parameter must match"
        );
        let output = parsed.hash.expect("output present");
        assert_eq!(output.len(), ARGON2_OUTPUT_LEN, "Output must be 32 bytes");
        let salt = parsed.salt.expect("salt present");
        assert_eq!(salt.len(), 22, "Salt must be 16 bytes (22 base64 chars)");
    }

    // ───────────────────────────────────────────────────────────
    // 3. UNICODE / NFKC NORMALIZATION
    // ───────────────────────────────────────────────────────────

    #[test]
    fn nfkc_composed_vs_decomposed_angstrom() {
        let hash = hash_password("\u{212B}").expect("hash");
        assert!(verify_password(&hash, "\u{00C5}").expect("verify"));
    }

    #[test]
    fn nfkc_composed_vs_decomposed_e_acute() {
        let precomposed = "\u{00E9}";
        let decomposed = "\u{0065}\u{0301}";
        let hash = hash_password(precomposed).expect("hash");
        assert!(verify_password(&hash, decomposed).expect("verify"));
    }

    #[test]
    fn nfkc_fullwidth_to_ascii() {
        let hash = hash_password("\u{FF21}").expect("hash");
        assert!(verify_password(&hash, "A").expect("verify"));
    }

    #[test]
    fn nfkc_roman_numeral_ligature() {
        let hash = hash_password("\u{2162}").expect("hash");
        assert!(verify_password(&hash, "III").expect("verify"));
    }

    #[test]
    fn nfkc_superscript_digits() {
        let hash = hash_password("\u{00B2}").expect("hash");
        assert!(verify_password(&hash, "2").expect("verify"));
    }

    // ───────────────────────────────────────────────────────────
    // 4. INPUT VALIDATION & BOUNDARY CONDITIONS
    // ───────────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_password() {
        let err = hash_password("").unwrap_err();
        assert!(matches!(err, HashError::EmptyPassword), "Error: {err}");
    }

    #[test]
    fn rejects_oversized_password() {
        let big = "a".repeat(MAX_PASSWORD_LENGTH + 1);
        let err = hash_password(&big).unwrap_err();
        assert!(matches!(err, HashError::PasswordTooLong(_)), "Error: {err}");
    }

    #[test]
    fn accepts_max_length_password() {
        let max = "a".repeat(MAX_PASSWORD_LENGTH);
        let hash = hash_password(&max).expect("hash at max length");
        assert!(verify_password(&hash, &max).expect("verify"));
    }

    #[test]
    fn rejects_empty_hash_on_verify() {
        let err = verify_password("", "password").unwrap_err();
        assert!(matches!(err, HashError::EmptyHash), "Error: {err}");
    }

    #[test]
    fn rejects_oversized_hash_on_verify() {
        let big_hash = "a".repeat(MAX_HASH_LENGTH + 1);
        let err = verify_password(&big_hash, "password").unwrap_err();
        assert!(matches!(err, HashError::HashTooLong(_)), "Error: {err}");
    }

    #[test]
    fn rejects_malformed_hash_on_verify() {
        let err = verify_password("not-a-valid-hash", "password").unwrap_err();
        assert!(matches!(err, HashError::InvalidHash(_)), "Error: {err}");
    }

    // ───────────────────────────────────────────────────────────
    // 5. SPECIAL CHARACTER PASSWORDS
    // ───────────────────────────────────────────────────────────

    #[test]
    fn handles_null_bytes_in_password() {
        let pw = "before\0after";
        let hash = hash_password(pw).expect("hash");
        assert!(verify_password(&hash, pw).expect("verify"));
        assert!(!verify_password(&hash, "before").expect("verify prefix"));
    }

    #[test]
    fn handles_emoji_password() {
        let pw = "🔑🏦💰🔐";
        let hash = hash_password(pw).expect("hash");
        assert!(verify_password(&hash, pw).expect("verify"));
    }

    #[test]
    fn handles_mixed_script_password() {
        let pw = "Pässwörd密码パスワード";
        let hash = hash_password(pw).expect("hash");
        assert!(verify_password(&hash, pw).expect("verify"));
    }

    #[test]
    fn handles_rtl_script_password() {
        let pw = "كلمة السر";
        let hash = hash_password(pw).expect("hash");
        assert!(verify_password(&hash, pw).expect("verify"));
    }

    #[test]
    fn handles_whitespace_only_password() {
        let pw = "   \t\n  ";
        let hash = hash_password(pw).expect("hash");
        assert!(verify_password(&hash, pw).expect("verify"));
    }

    // ───────────────────────────────────────────────────────────
    // 6. TIMING CHARACTERISTICS
    // ───────────────────────────────────────────────────────────

    #[test]
    fn hash_takes_nontrivial_time() {
        let start = Instant::now();
        let _ = hash_password("timing-test").expect("hash");
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() >= 10,
            "Hash should take at least 10ms to resist brute-force; took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn verify_takes_nontrivial_time() {
        let hash = hash_password("timing-test").expect("hash");
        let start = Instant::now();
        let _ = verify_password(&hash, "timing-test").expect("verify");
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() >= 10,
            "Verify should take at least 10ms; took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn timing_consistency_correct_vs_wrong() {
        let hash = hash_password("timing-test").expect("hash");

        let mut correct_times = Vec::new();
        let mut wrong_times = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            let _ = verify_password(&hash, "timing-test").expect("verify correct");
            correct_times.push(start.elapsed().as_micros());

            let start = Instant::now();
            let _ = verify_password(&hash, "wrong-password").expect("verify wrong");
            wrong_times.push(start.elapsed().as_micros());
        }

        let avg_correct: u128 = correct_times.iter().sum::<u128>() / correct_times.len() as u128;
        let avg_wrong: u128 = wrong_times.iter().sum::<u128>() / wrong_times.len() as u128;

        let ratio = if avg_correct > avg_wrong {
            avg_correct as f64 / avg_wrong as f64
        } else {
            avg_wrong as f64 / avg_correct as f64
        };

        assert!(
            ratio < 2.0,
            "Timing ratio between correct/wrong verification should be < 2x \
             (got {ratio:.2}x, correct={avg_correct}µs, wrong={avg_wrong}µs). \
             Large differences may indicate timing side-channel vulnerability."
        );
    }

    // ───────────────────────────────────────────────────────────
    // 7. CROSS-REFERENCE / INTEROPERABILITY
    // ───────────────────────────────────────────────────────────

    #[test]
    fn case_sensitivity() {
        let hash = hash_password("Password123").expect("hash");
        assert!(!verify_password(&hash, "password123").expect("lowercase"));
        assert!(!verify_password(&hash, "PASSWORD123").expect("uppercase"));
        assert!(verify_password(&hash, "Password123").expect("exact"));
    }

    #[test]
    fn rejects_argon2i_hash() {
        let argon2i_hash = "$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$KnPkRpJMfRMGcOkaw9MxOYbJM/VHoHJlkLeYN0zVtF4";
        let err = verify_password(argon2i_hash, "password").unwrap_err();
        assert!(
            matches!(err, HashError::UnsupportedAlgorithm),
            "Error: {err}"
        );
    }

    #[test]
    fn rejects_argon2d_hash() {
        let argon2d_hash = "$argon2d$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$KnPkRpJMfRMGcOkaw9MxOYbJM/VHoHJlkLeYN0zVtF4";
        let err = verify_password(argon2d_hash, "password").unwrap_err();
        assert!(
            matches!(err, HashError::UnsupportedAlgorithm),
            "Error: {err}"
        );
    }

    // ───────────────────────────────────────────────────────────
    // 8. SEQUENTIAL STRESS
    // ───────────────────────────────────────────────────────────

    #[test]
    fn sequential_hash_verify_stress() {
        for i in 0..20 {
            let pw = format!("stress-test-password-{i}");
            let hash = hash_password(&pw).expect("hash");
            assert!(verify_password(&hash, &pw).expect("verify"));
        }
    }

    #[test]
    fn hash_verify_with_varying_password_lengths() {
        for len in [1, 2, 4, 8, 16, 32, 64, 128] {
            let pw: String = "x".repeat(len);
            let hash = hash_password(&pw).unwrap_or_else(|_| panic!("hash len={len}"));
            assert!(
                verify_password(&hash, &pw).unwrap_or_else(|_| panic!("verify len={len}")),
                "Failed at password length {len}"
            );
        }
    }

    // ───────────────────────────────────────────────────────────
    // 9. NFKC EXPANSION BOUNDARY
    // ───────────────────────────────────────────────────────────

    #[test]
    fn rejects_password_whose_nfkc_exceeds_limit() {
        // U+3300 (㌀ SQUARE APAATO) is 3 UTF-8 bytes but NFKC-expands to
        // アパート (4 chars × 3 bytes = 12 bytes). 42 copies = 126 bytes
        // input (within limit), but 504 bytes after NFKC (over limit).
        let pw: String = "\u{3300}".repeat(42);
        assert!(
            pw.len() <= MAX_PASSWORD_LENGTH,
            "precondition: raw bytes fit"
        );
        let err = hash_password(&pw).unwrap_err();
        assert!(
            matches!(err, HashError::NormalizedPasswordTooLong(_)),
            "Expected NormalizedPasswordTooLong, got: {err}"
        );
    }

    // ───────────────────────────────────────────────────────────
    // 10. ERROR CODES
    // ───────────────────────────────────────────────────────────

    #[test]
    fn error_codes_follow_category_convention() {
        let validation_errors: Vec<HashError> = vec![
            HashError::EmptyPassword,
            HashError::PasswordTooLong(128),
            HashError::NormalizedPasswordTooLong(128),
            HashError::EmptyHash,
            HashError::HashTooLong(4096),
            HashError::InvalidHash("test".into()),
            HashError::UnsupportedAlgorithm,
        ];
        for e in &validation_errors {
            assert!(
                e.code().starts_with("VALIDATION_"),
                "{:?} code should start with VALIDATION_, got {}",
                e,
                e.code()
            );
        }

        let crypto_errors: Vec<HashError> = vec![
            HashError::HashingFailed("test".into()),
            HashError::VerificationFailed("test".into()),
            HashError::RngFailed("test".into()),
            HashError::SaltEncodingFailed("test".into()),
        ];
        for e in &crypto_errors {
            assert!(
                e.code().starts_with("CRYPTO_"),
                "{:?} code should start with CRYPTO_, got {}",
                e,
                e.code()
            );
        }
    }
}
