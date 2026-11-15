-- Full addresses of attack requests, and events from the service manager.

-- The query string, stored only for requests flagged as probes. A visitor's
-- query string can hold private tokens, so it is never kept.
ALTER TABLE http_requests ADD COLUMN query TEXT;

CREATE TABLE system_events (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    kind   TEXT    NOT NULL,      -- service_failed
    name   TEXT    NOT NULL,      -- the unit, such as certbot.service
    detail TEXT
);
CREATE INDEX system_events_ts ON system_events (ts);
CREATE INDEX security_events_kind ON security_events (kind, ts);
