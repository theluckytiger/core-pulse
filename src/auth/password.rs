//! Password hashing with argon2id (the argon2 crate's defaults: 19 MiB, 2 passes).

use std::sync::LazyLock;

use anyhow::{Result, anyhow, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub const MIN_LENGTH: usize = 12;
const MAX_LENGTH: usize = 1024;

pub fn hash(password: &str) -> Result<String> {
    ensure!(
        password.chars().count() >= MIN_LENGTH,
        "password must have at least {MIN_LENGTH} characters"
    );
    ensure!(password.len() <= MAX_LENGTH, "password is too long");
    // A random salt is generated for every hash.
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("{e}"))?;
    Ok(hash.to_string())
}

pub fn verify(password: &str, hash: &str) -> bool {
    password.len() <= MAX_LENGTH
        && PasswordHash::new(hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
}

/// Verifying against this when the user does not exist makes the response
/// take as long as for a real user, so timing does not reveal usernames.
pub fn verify_dummy(password: &str) {
    static DUMMY: LazyLock<Option<String>> = LazyLock::new(|| hash("not a real password").ok());
    if let Some(dummy) = DUMMY.as_deref() {
        verify(password, dummy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies() {
        let hashed = hash("correct horse battery").unwrap();
        assert!(hashed.starts_with("$argon2id$"));
        assert!(verify("correct horse battery", &hashed));
        assert!(!verify("correct horse batterY", &hashed));
    }

    #[test]
    fn salts_every_hash() {
        assert_ne!(
            hash("correct horse battery").unwrap(),
            hash("correct horse battery").unwrap()
        );
    }

    #[test]
    fn rejects_short_passwords_and_bad_hashes() {
        assert!(hash("short").is_err());
        assert!(!verify("anything at all", "not a hash"));
    }
}
