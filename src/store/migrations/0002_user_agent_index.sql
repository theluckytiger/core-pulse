-- Speeds up top user agents and the cleanup of unused ones.
CREATE INDEX http_requests_ua ON http_requests (ua_id);
