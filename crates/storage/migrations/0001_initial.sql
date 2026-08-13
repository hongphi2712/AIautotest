CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    target_host  TEXT NOT NULL DEFAULT '',
    start_time   TEXT NOT NULL,
    end_time     TEXT,
    flow_count   INTEGER NOT NULL DEFAULT 0,
    notes        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS flows (
    id                    TEXT PRIMARY KEY NOT NULL,
    session_id            TEXT NOT NULL DEFAULT '',
    timestamp             TEXT NOT NULL,
    method                TEXT NOT NULL,
    host                  TEXT NOT NULL DEFAULT '',
    ip                    TEXT NOT NULL DEFAULT '',
    path                  TEXT NOT NULL DEFAULT '',
    full_url              TEXT NOT NULL DEFAULT '',
    request_headers       TEXT NOT NULL DEFAULT '{}',
    request_body          TEXT,
    request_cookies       TEXT NOT NULL DEFAULT '[]',
    request_cookie_values TEXT NOT NULL DEFAULT '{}',
    response_status       INTEGER NOT NULL DEFAULT 0,
    response_headers      TEXT NOT NULL DEFAULT '{}',
    response_body         TEXT,
    response_cookies      TEXT NOT NULL DEFAULT '[]',
    response_cookie_values TEXT NOT NULL DEFAULT '{}',
    content_type          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_flows_session_id ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
