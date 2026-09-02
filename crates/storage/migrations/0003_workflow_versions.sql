CREATE TABLE IF NOT EXISTS workflow_versions (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    base_url    TEXT NOT NULL,
    spec_json   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'draft',
    created_at  TEXT NOT NULL,
    approved_at TEXT
);