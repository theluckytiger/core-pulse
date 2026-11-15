-- Raw events, hourly totals and the read position of each log source.

CREATE TABLE user_agents (
    id    INTEGER PRIMARY KEY,
    value TEXT NOT NULL UNIQUE
);

CREATE TABLE http_requests (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,   -- unix seconds
    site      TEXT    NOT NULL,
    client_ip TEXT    NOT NULL,   -- visitor, after trusted proxies
    peer_ip   TEXT    NOT NULL,   -- address that connected to nginx
    method    TEXT    NOT NULL,
    path      TEXT    NOT NULL,   -- without the query string
    status    INTEGER NOT NULL,
    bytes     INTEGER NOT NULL,
    ua_id     INTEGER REFERENCES user_agents (id),
    probe     TEXT                -- matched probe rule, if any
);
CREATE INDEX http_requests_ts ON http_requests (ts);
CREATE INDEX http_requests_probe ON http_requests (probe, ts) WHERE probe IS NOT NULL;

CREATE TABLE security_events (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    kind   TEXT    NOT NULL,      -- ban, unban, ssh_fail, ssh_login, fw_block
    source TEXT    NOT NULL,      -- fail2ban jail, sshd or ufw
    ip     TEXT    NOT NULL,
    port   INTEGER,
    detail TEXT
);
CREATE INDEX security_events_ts ON security_events (ts);
CREATE INDEX security_events_ip ON security_events (ip, ts);

-- Counters per hour, kept longer than raw events.
CREATE TABLE hourly_totals (
    hour   INTEGER NOT NULL,      -- unix seconds at the start of the hour
    metric TEXT    NOT NULL,      -- for example http.status or sec.kind
    name   TEXT    NOT NULL,
    value  INTEGER NOT NULL,
    PRIMARY KEY (hour, metric, name)
) WITHOUT ROWID;

-- Where each source stopped reading, so restarts lose and repeat nothing.
CREATE TABLE source_state (
    source   TEXT PRIMARY KEY,
    file_id  TEXT,                -- device and inode of the file being read
    position INTEGER,             -- byte offset in that file
    cursor   TEXT,                -- journald cursor
    updated  INTEGER NOT NULL
);
