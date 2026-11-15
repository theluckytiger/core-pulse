-- Dashboard users and their server-side sessions.

CREATE TABLE users (
    id             INTEGER PRIMARY KEY,
    username       TEXT    NOT NULL UNIQUE,
    password_hash  TEXT    NOT NULL,   -- argon2id, PHC string format
    totp_secret    BLOB    NOT NULL,
    totp_last_step INTEGER,            -- last accepted code step; a code works once
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER,            -- unix seconds
    created        INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB    PRIMARY KEY,    -- SHA-256 of the cookie value, never the value
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    created    INTEGER NOT NULL,
    expires    INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    client_ip  TEXT    NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires);
