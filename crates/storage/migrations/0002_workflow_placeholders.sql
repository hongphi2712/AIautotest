CREATE TABLE IF NOT EXISTS workflow_nodes (
    workflow_id  TEXT NOT NULL,
    node_id      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    position_x   INTEGER NOT NULL DEFAULT 0,
    position_y   INTEGER NOT NULL DEFAULT 0,
    config_json  TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (workflow_id, node_id)
);

CREATE TABLE IF NOT EXISTS workflow_edges (
    workflow_id      TEXT NOT NULL,
    edge_id          TEXT NOT NULL,
    source_node_id   TEXT NOT NULL,
    target_node_id   TEXT NOT NULL,
    PRIMARY KEY (workflow_id, edge_id)
);

CREATE TABLE IF NOT EXISTS workflow_runs (
    run_id        TEXT PRIMARY KEY NOT NULL,
    workflow_id   TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    status        TEXT NOT NULL DEFAULT 'queued',
    results_json  TEXT NOT NULL DEFAULT '{}'
);
