//! Users and sessions. The rules (lockout, expiry) live in `auth`; this is
//! only storage.

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Row, params};

use super::Store;

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub totp_secret: Vec<u8>,
    pub totp_last_step: Option<u64>,
    pub failed_logins: u32,
    pub locked_until: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub csrf_token: String,
    pub expires: i64,
    pub last_seen: i64,
}

pub struct NewSession<'a> {
    pub token_hash: &'a [u8],
    pub user_id: i64,
    pub csrf_token: &'a str,
    pub now: i64,
    pub expires: i64,
    pub client_ip: &'a str,
}

fn user_from_row(row: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        totp_secret: row.get(3)?,
        totp_last_step: row.get::<_, Option<i64>>(4)?.map(i64::unsigned_abs),
        failed_logins: row.get(5)?,
        locked_until: row.get(6)?,
    })
}

const USER_COLUMNS: &str =
    "id, username, password_hash, totp_secret, totp_last_step, failed_logins, locked_until";

impl Store {
    pub fn add_user(
        &mut self,
        username: &str,
        password_hash: &str,
        totp_secret: &[u8],
        now: i64,
    ) -> Result<()> {
        ensure!(
            self.user(username)?.is_none(),
            "user {username} already exists"
        );
        self.conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret, created) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, totp_secret, now],
        )?;
        Ok(())
    }

    pub fn user(&self, username: &str) -> Result<Option<User>> {
        let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1");
        Ok(self
            .conn
            .query_row(&sql, [username], user_from_row)
            .optional()?)
    }

    pub fn users(&self) -> Result<Vec<User>> {
        let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY username");
        let mut stmt = self.conn.prepare(&sql)?;
        let users = stmt
            .query_map([], user_from_row)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(users)
    }

    /// Counts a failed login and locks the account once `max_failures` is reached.
    pub fn record_failed_login(
        &self,
        user_id: i64,
        max_failures: u32,
        lock_until: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE users SET failed_logins = failed_logins + 1,
                 locked_until = CASE WHEN failed_logins + 1 >= ?2 THEN ?3 ELSE locked_until END
             WHERE id = ?1",
            params![user_id, max_failures, lock_until],
        )?;
        Ok(())
    }

    pub fn record_login(&self, user_id: i64, totp_step: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL, totp_last_step = ?2 WHERE id = ?1",
            params![user_id, i64::try_from(totp_step).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }

    pub fn set_password(&self, username: &str, password_hash: &str) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET password_hash = ?2 WHERE username = ?1",
            params![username, password_hash],
        )?;
        self.end_sessions(username, changed)
    }

    pub fn set_totp_secret(&self, username: &str, secret: &[u8]) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET totp_secret = ?2, totp_last_step = NULL WHERE username = ?1",
            params![username, secret],
        )?;
        self.end_sessions(username, changed)
    }

    pub fn unlock_user(&self, username: &str) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = ?1",
            [username],
        )?;
        ensure!(changed > 0, "no user named {username}");
        Ok(())
    }

    pub fn remove_user(&self, username: &str) -> Result<()> {
        // Sessions go with the user (ON DELETE CASCADE).
        let removed = self
            .conn
            .execute("DELETE FROM users WHERE username = ?1", [username])?;
        ensure!(removed > 0, "no user named {username}");
        Ok(())
    }

    /// After a password or 2FA change: sign the user out everywhere.
    fn end_sessions(&self, username: &str, changed: usize) -> Result<()> {
        ensure!(changed > 0, "no user named {username}");
        self.conn.execute(
            "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?1)",
            [username],
        )?;
        Ok(())
    }

    pub fn create_session(&self, s: &NewSession) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created, expires, last_seen, client_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6)",
            params![s.token_hash, s.user_id, s.csrf_token, s.now, s.expires, s.client_ip],
        )?;
        Ok(())
    }

    pub fn session(&self, token_hash: &[u8]) -> Result<Option<Session>> {
        let session = self
            .conn
            .query_row(
                "SELECT u.username, s.csrf_token, s.expires, s.last_seen
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1",
                [token_hash],
                |row| {
                    Ok(Session {
                        username: row.get(0)?,
                        csrf_token: row.get(1)?,
                        expires: row.get(2)?,
                        last_seen: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(session)
    }

    pub fn touch_session(&self, token_hash: &[u8], now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET last_seen = ?2 WHERE token_hash = ?1",
            params![token_hash, now],
        )?;
        Ok(())
    }

    pub fn delete_session(&self, token_hash: &[u8]) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
        Ok(())
    }

    pub fn delete_stale_sessions(&self, now: i64, idle_cutoff: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE expires <= ?1 OR last_seen <= ?2",
            params![now, idle_cutoff],
        )?;
        Ok(())
    }
}
