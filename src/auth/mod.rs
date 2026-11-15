//! Dashboard login: argon2id passwords, a required TOTP code, server-side
//! sessions and a lockout after repeated failures.

mod limiter;
pub mod password;
pub mod totp;

use anyhow::{Context, Result, ensure};
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::clock::{HOUR, MINUTE};
use crate::store::Store;
use crate::store::users::{NewSession, Session};

pub use limiter::Limiter;

/// Failed logins in a row before the account locks.
pub const MAX_FAILURES: u32 = 5;
pub const LOCK_TIME: i64 = 15 * MINUTE;
pub const SESSION_LIFETIME: i64 = 12 * HOUR;
pub const IDLE_TIMEOUT: i64 = 2 * HOUR;

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    /// Wrong user, password or code. The visitor is never told which.
    Invalid,
    Locked,
}

/// A new session. `token` goes into the cookie and is shown nowhere else.
pub struct SignedIn {
    pub token: String,
    pub expires: i64,
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
    Ok(bytes)
}

pub fn random_token() -> Result<String> {
    Ok(BASE64URL_NOPAD.encode(&random_bytes::<32>()?))
}

/// Only a hash of the session token is stored, so a copy of the database
/// cannot be used to take over a session.
pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn validate_username(name: &str) -> Result<()> {
    let ok = (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    ensure!(ok, "usernames use 1 to 32 of a-z, 0-9, '.', '_' and '-'");
    Ok(())
}

/// Checks username, password and code together and opens a session.
pub fn login(
    store: &Store,
    username: &str,
    password: &str,
    code: &str,
    client_ip: &str,
    now: i64,
) -> Result<Result<SignedIn, LoginError>> {
    let Some(user) = store.user(username)? else {
        password::verify_dummy(password);
        return Ok(Err(LoginError::Invalid));
    };
    if user.locked_until.is_some_and(|until| until > now) {
        return Ok(Err(LoginError::Locked));
    }

    let password_ok = password::verify(password, &user.password_hash);
    let step = totp::verify(&user.totp_secret, code, now, user.totp_last_step);
    let Some(step) = step.filter(|_| password_ok) else {
        store.record_failed_login(user.id, MAX_FAILURES, now + LOCK_TIME)?;
        return Ok(Err(LoginError::Invalid));
    };

    store.record_login(user.id, step)?;
    let token = random_token()?;
    let csrf_token = random_token()?;
    let expires = now + SESSION_LIFETIME;
    store
        .create_session(&NewSession {
            token_hash: &token_hash(&token),
            user_id: user.id,
            csrf_token: &csrf_token,
            now,
            expires,
            client_ip,
        })
        .context("cannot create session")?;
    Ok(Ok(SignedIn { token, expires }))
}

/// The session for a cookie value, if it is still valid. Refreshes its
/// last-seen time about once a minute.
pub fn session(store: &Store, token: &str, now: i64) -> Result<Option<Session>> {
    let hash = token_hash(token);
    let Some(session) = store.session(&hash)? else {
        return Ok(None);
    };
    if session.expires <= now || session.last_seen + IDLE_TIMEOUT <= now {
        store.delete_session(&hash)?;
        return Ok(None);
    }
    if now - session.last_seen >= MINUTE {
        store.touch_session(&hash, now)?;
    }
    Ok(Some(session))
}

pub fn logout(store: &Store, token: &str) -> Result<()> {
    store.delete_session(&token_hash(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_794_670_407;
    const PASSWORD: &str = "correct horse battery";
    const SECRET: &[u8] = b"12345678901234567890";

    fn store_with_user() -> Store {
        let mut store = Store::open_in_memory().unwrap();
        store
            .add_user("admin", &password::hash(PASSWORD).unwrap(), SECRET, NOW)
            .unwrap();
        store
    }

    fn code_at(now: i64) -> String {
        totp::code_at(SECRET, now)
    }

    #[test]
    fn signs_in_with_password_and_code() {
        let store = store_with_user();
        let signed_in = login(&store, "admin", PASSWORD, &code_at(NOW), "192.0.2.1", NOW)
            .unwrap()
            .unwrap();
        let session = session(&store, &signed_in.token, NOW + 10)
            .unwrap()
            .unwrap();
        assert_eq!(session.username, "admin");
        assert_eq!(session.csrf_token.len(), 43);
    }

    #[test]
    fn needs_both_password_and_code() {
        let store = store_with_user();
        let code = code_at(NOW);
        let wrong_password =
            login(&store, "admin", "wrong password!!", &code, "192.0.2.1", NOW).unwrap();
        assert_eq!(wrong_password.err(), Some(LoginError::Invalid));
        let wrong_code = login(&store, "admin", PASSWORD, "000000", "192.0.2.1", NOW).unwrap();
        assert_eq!(wrong_code.err(), Some(LoginError::Invalid));
        let unknown = login(&store, "nobody", PASSWORD, &code, "192.0.2.1", NOW).unwrap();
        assert_eq!(unknown.err(), Some(LoginError::Invalid));
    }

    #[test]
    fn a_code_cannot_be_used_twice() {
        let store = store_with_user();
        let code = code_at(NOW);
        assert!(
            login(&store, "admin", PASSWORD, &code, "192.0.2.1", NOW)
                .unwrap()
                .is_ok()
        );
        let again = login(&store, "admin", PASSWORD, &code, "192.0.2.1", NOW + 1).unwrap();
        assert_eq!(again.err(), Some(LoginError::Invalid));
    }

    #[test]
    fn locks_after_repeated_failures() {
        let store = store_with_user();
        for _ in 0..MAX_FAILURES {
            login(
                &store,
                "admin",
                "wrong password!!",
                "000000",
                "192.0.2.1",
                NOW,
            )
            .unwrap()
            .ok();
        }
        // Even the right password and code are refused while locked.
        let locked = login(&store, "admin", PASSWORD, &code_at(NOW), "192.0.2.1", NOW).unwrap();
        assert_eq!(locked.err(), Some(LoginError::Locked));

        let later = NOW + LOCK_TIME + 60;
        assert!(
            login(
                &store,
                "admin",
                PASSWORD,
                &code_at(later),
                "192.0.2.1",
                later
            )
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn sessions_expire_when_idle_and_on_logout() {
        let store = store_with_user();
        let signed_in = login(&store, "admin", PASSWORD, &code_at(NOW), "192.0.2.1", NOW)
            .unwrap()
            .unwrap();
        assert!(
            session(&store, &signed_in.token, NOW + IDLE_TIMEOUT + 1)
                .unwrap()
                .is_none()
        );

        let later = NOW + 3600;
        let signed_in = login(
            &store,
            "admin",
            PASSWORD,
            &code_at(later),
            "192.0.2.1",
            later,
        )
        .unwrap()
        .unwrap();
        logout(&store, &signed_in.token).unwrap();
        assert!(session(&store, &signed_in.token, later).unwrap().is_none());
        assert!(session(&store, "made-up-token", later).unwrap().is_none());
    }

    #[test]
    fn password_change_ends_sessions() {
        let store = store_with_user();
        let signed_in = login(&store, "admin", PASSWORD, &code_at(NOW), "192.0.2.1", NOW)
            .unwrap()
            .unwrap();
        store
            .set_password("admin", &password::hash("another long password").unwrap())
            .unwrap();
        assert!(session(&store, &signed_in.token, NOW).unwrap().is_none());
    }

    #[test]
    fn checks_usernames() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("ops-1.backup_x").is_ok());
        for bad in ["", "Admin", "a b", "x".repeat(33).as_str(), "name;drop"] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
    }
}
