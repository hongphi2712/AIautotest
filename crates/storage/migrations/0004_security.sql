CREATE TABLE IF NOT EXISTS security_plans (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    base_url    TEXT NOT NULL,
    plan_json   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'draft',
    created_at  TEXT NOT NULL,
    approved_at TEXT
);

CREATE TABLE IF NOT EXISTS security_runs (
    run_id      TEXT PRIMARY KEY NOT NULL,
    plan_id     TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'queued',
    findings_json TEXT NOT NULL DEFAULT '[]'
);
