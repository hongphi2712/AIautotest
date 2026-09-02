use std::str::FromStr;

use api_tester_domain::{
    HttpFlow, HttpMethod, SecurityPlan, SecurityRun, Session, SitemapAnnotation, WorkflowRun,
    WorkflowVersion,
};
use api_tester_ports::{
    AnnotationRepository, FlowRepository, PortError, SecurityRepository, SessionRepository,
    WorkflowRepository,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Connection;
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePoolOptions, SqliteRow,
};
use sqlx::{Pool, Sqlite};

use crate::error::StorageError;

const DEFAULT_MAX_CONNECTIONS: u32 = 4;

#[derive(Clone)]
pub struct SqliteStore {
    pool: Pool<Sqlite>,
    flows: SqliteFlowRepository,
    sessions: SqliteSessionRepository,
    workflows: SqliteWorkflowRepository,
    security: SqliteSecurityRepository,
    annotations: SqliteAnnotationRepository,
}

#[derive(Clone)]
pub struct SqliteFlowRepository {
    pool: Pool<Sqlite>,
}

#[derive(Clone)]
pub struct SqliteSessionRepository {
    pool: Pool<Sqlite>,
}

#[derive(Clone)]
pub struct SqliteWorkflowRepository {
    pool: Pool<Sqlite>,
}

#[derive(Clone)]
pub struct SqliteSecurityRepository {
    pool: Pool<Sqlite>,
}

#[derive(Clone)]
pub struct SqliteAnnotationRepository {
    pool: Pool<Sqlite>,
}

impl SqliteStore {
    pub async fn open(database_url: &str) -> Result<Self, StorageError> {
        Self::open_with_pool_size(database_url, DEFAULT_MAX_CONNECTIONS).await
    }

    pub async fn open_with_pool_size(
        database_url: &str,
        max_connections: u32,
    ) -> Result<Self, StorageError> {
        match Self::try_open(database_url, max_connections).await {
            Ok(store) => Ok(store),
            Err(error) if is_readonly_storage_error(&error) => {
                eprintln!(
                    "[storage] database opened read-only ({error}); attempting stale WAL/SHM recovery"
                );
                Self::recover_readonly(database_url).await?;
                Self::try_open(database_url, max_connections).await
            }
            Err(error) => Err(error),
        }
    }

    async fn try_open(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let max_connections = max_connections.max(1);
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(|error| StorageError::Connect(error.to_string()))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(30));

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await
            .map_err(|error| StorageError::Connect(error.to_string()))?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        // Probe with a real write. Opening and reading succeed even when the
        // WAL/SHM side files are stale or locked; the first write is where
        // SQLITE_READONLY (code 8) surfaces. Fail here with the full context
        // instead of letting the proxy's first session INSERT blow up.
        if let Err(error) =
            sqlx::query("CREATE TABLE IF NOT EXISTS storage_write_probe (ok INTEGER NOT NULL)")
                .execute(&pool)
                .await
        {
            pool.close().await;
            return Err(StorageError::Sqlx(error));
        }
        let _ = sqlx::query("DROP TABLE IF EXISTS storage_write_probe")
            .execute(&pool)
            .await;

        Ok(Self {
            pool: pool.clone(),
            flows: SqliteFlowRepository { pool: pool.clone() },
            sessions: SqliteSessionRepository { pool: pool.clone() },
            workflows: SqliteWorkflowRepository { pool: pool.clone() },
            security: SqliteSecurityRepository { pool: pool.clone() },
            annotations: SqliteAnnotationRepository { pool },
        })
    }

    /// Heals the stale-lock state left behind by force-killed instances:
    /// checkpoint what can be checkpointed, back up the main db file, then
    /// remove the `-shm`/`-wal` side files so the next open rebuilds them.
    /// Only called after a readonly probe failure; safe because the app holds
    /// a single-instance lock on `server.lock`.
    async fn recover_readonly(database_url: &str) -> Result<(), StorageError> {
        use std::path::Path;

        let db_path = Path::new(database_url);
        let wal_path = format!("{database_url}-wal");
        let shm_path = format!("{database_url}-shm");
        let wal = Path::new(&wal_path);
        let shm = Path::new(&shm_path);

        // Last-chance in-place recovery through one dedicated connection.
        if let Ok(options) = SqliteConnectOptions::from_str(database_url)
            .map(|o| o.journal_mode(SqliteJournalMode::Wal))
        {
            if let Ok(mut conn) = SqliteConnection::connect_with(&options).await {
                let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                    .execute(&mut conn)
                    .await;
                let _ = conn.close().await;
            }
        }

        // Small settle delay so lingering OS handles from a just-killed
        // process are released before we touch the side files.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        for side in [wal, shm] {
            if side.exists() {
                // Copy aside first: the -wal may hold committed transactions
                // that were never checkpointed, so never hard-delete blindly.
                let backup = side.with_extension(format!(
                    "{}.recovery.bak",
                    side.extension().and_then(|e| e.to_str()).unwrap_or("side")
                ));
                let _ = std::fs::copy(side, &backup);
                match std::fs::remove_file(side) {
                    Ok(()) => eprintln!("[storage] removed stale {}", side.display()),
                    Err(error) => {
                        return Err(StorageError::Connect(format!(
                            "cannot remove {} while another process may hold the database: {error}",
                            side.display()
                        )));
                    }
                }
            }
        }

        // Keep a forensic copy of the main file; recreating it fresh beats
        // staying permanently read-only for a capture-history dev tool.
        if db_path.exists() {
            let backup = db_path.with_extension("db.readonly-recovery.bak");
            let _ = std::fs::copy(db_path, &backup);
        }
        Ok(())
    }

    pub fn flows(&self) -> &SqliteFlowRepository {
        &self.flows
    }

    pub fn sessions(&self) -> &SqliteSessionRepository {
        &self.sessions
    }

    pub fn workflows(&self) -> &SqliteWorkflowRepository {
        &self.workflows
    }

    pub fn security(&self) -> &SqliteSecurityRepository {
        &self.security
    }

    pub fn annotations(&self) -> &SqliteAnnotationRepository {
        &self.annotations
    }

    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    pub async fn table_exists(&self, name: &str) -> Result<bool, StorageError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }
}

#[async_trait]
impl FlowRepository for SqliteFlowRepository {
    async fn save(&self, flow: &HttpFlow) -> Result<(), PortError> {
        let mut connection = self.pool.acquire().await.map_err(port_error)?;
        upsert_flow(connection.as_mut(), flow).await
    }

    async fn save_batch(&self, flows: &[HttpFlow]) -> Result<(), PortError> {
        let mut transaction = self.pool.begin().await.map_err(port_error)?;
        for flow in flows {
            upsert_flow(transaction.as_mut(), flow).await?;
        }
        transaction.commit().await.map_err(port_error)?;
        Ok(())
    }

    async fn get_by_id(&self, flow_id: &str) -> Result<Option<HttpFlow>, PortError> {
        let row = sqlx::query(SELECT_FLOW)
            .bind(flow_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(port_error)?;
        row.as_ref()
            .map(flow_from_row)
            .transpose()
            .map_err(port_error)
    }

    async fn list_by_session(&self, session_id: &str) -> Result<Vec<HttpFlow>, PortError> {
        let rows = sqlx::query(
            "SELECT id, session_id, timestamp, method, host, ip, path, full_url,
                    request_headers, request_body, request_cookies, request_cookie_values,
                    response_status, response_headers, response_body, response_cookies,
                    response_cookie_values, content_type
             FROM flows
             WHERE session_id = ?
             ORDER BY timestamp",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(flow_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }

    async fn clear_all(&self) -> Result<(), PortError> {
        sqlx::query("DELETE FROM flows")
            .execute(&self.pool)
            .await
            .map_err(port_error)?;
        Ok(())
    }
}

impl SqliteFlowRepository {
    /// Total persisted flows across all sessions. Used by the dashboard count,
    /// which avoids materializing `list_recent` rows on the 2s health poll.
    pub async fn count(&self) -> Result<u64, PortError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM flows")
            .fetch_one(&self.pool)
            .await
            .map_err(port_error)
    }

    /// Summary-only rows for a specific session (no bodies/headers).
    pub async fn list_by_session_meta(
        &self,
        session_id: &str,
        limit: u64,
    ) -> Result<Vec<HttpFlow>, PortError> {
        let rows = sqlx::query(
            "SELECT id, session_id, timestamp, method, host, ip, path, full_url,
                    request_cookies, request_cookie_values, response_status,
                    response_cookies, response_cookie_values, content_type,
                    COALESCE(LENGTH(response_body), 0) AS response_body_len
             FROM flows
             WHERE session_id = ?
             ORDER BY timestamp DESC
             LIMIT ?",
        )
        .bind(session_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(flow_meta_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }
    /// Most recent flows across all sessions, newest first. Used by the
    /// dashboard to show persisted history after a restart.
    pub async fn list_recent(&self, limit: u64) -> Result<Vec<HttpFlow>, PortError> {
        let rows = sqlx::query(
            "SELECT id, session_id, timestamp, method, host, ip, path, full_url,
                    request_headers, request_body, request_cookies, request_cookie_values,
                    response_status, response_headers, response_body, response_cookies,
                    response_cookie_values, content_type
             FROM flows
             ORDER BY timestamp DESC
             LIMIT ?",
        )
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(flow_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }

    /// Summary-only rows (no request/response bodies or headers) for the
    /// dashboard table, so the 2s poll never reads body blobs. `response_body_len`
    /// is computed in SQL via `LENGTH()`.
    pub async fn list_recent_meta(&self, limit: u64) -> Result<Vec<HttpFlow>, PortError> {
        let rows = sqlx::query(
            "SELECT id, session_id, timestamp, method, host, ip, path, full_url,
                    request_cookies, request_cookie_values, response_status,
                    response_cookies, response_cookie_values, content_type,
                    COALESCE(LENGTH(response_body), 0) AS response_body_len
             FROM flows
             ORDER BY timestamp DESC
             LIMIT ?",
        )
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(flow_meta_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }
}

const FLOW_UPSERT: &str = "INSERT INTO flows (
             id, session_id, timestamp, method, host, ip, path, full_url,
             request_headers, request_body, request_cookies, request_cookie_values,
             response_status, response_headers, response_body, response_cookies,
             response_cookie_values, content_type
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
             session_id = excluded.session_id,
             timestamp = excluded.timestamp,
             method = excluded.method,
             host = excluded.host,
             ip = excluded.ip,
             path = excluded.path,
             full_url = excluded.full_url,
             request_headers = excluded.request_headers,
             request_body = excluded.request_body,
             request_cookies = excluded.request_cookies,
             request_cookie_values = excluded.request_cookie_values,
             response_status = excluded.response_status,
             response_headers = excluded.response_headers,
             response_body = excluded.response_body,
             response_cookies = excluded.response_cookies,
             response_cookie_values = excluded.response_cookie_values,
             content_type = excluded.content_type";

async fn upsert_flow(connection: &mut SqliteConnection, flow: &HttpFlow) -> Result<(), PortError> {
    sqlx::query(FLOW_UPSERT)
        .bind(&flow.id)
        .bind(&flow.session_id)
        .bind(flow.timestamp.to_rfc3339())
        .bind(flow.method.as_str())
        .bind(&flow.host)
        .bind(&flow.ip)
        .bind(&flow.path)
        .bind(&flow.full_url)
        .bind(serde_json::to_string(&flow.request_headers).map_err(storage_error)?)
        .bind(flow.request_body.as_deref())
        .bind(serde_json::to_string(&flow.request_cookies).map_err(storage_error)?)
        .bind(serde_json::to_string(&flow.request_cookie_values).map_err(storage_error)?)
        .bind(i64::from(flow.response_status))
        .bind(serde_json::to_string(&flow.response_headers).map_err(storage_error)?)
        .bind(flow.response_body.as_deref())
        .bind(serde_json::to_string(&flow.response_cookies).map_err(storage_error)?)
        .bind(serde_json::to_string(&flow.response_cookie_values).map_err(storage_error)?)
        .bind(&flow.content_type)
        .execute(&mut *connection)
        .await
        .map_err(port_error)?;
    Ok(())
}

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO sessions (id, name, target_host, start_time, end_time, flow_count, notes)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 target_host = excluded.target_host,
                 start_time = excluded.start_time,
                 end_time = excluded.end_time,
                 flow_count = excluded.flow_count,
                 notes = excluded.notes",
        )
        .bind(&session.id)
        .bind(&session.name)
        .bind(&session.target_host)
        .bind(session.start_time.to_rfc3339())
        .bind(session.end_time.map(|time| time.to_rfc3339()))
        .bind(i64::try_from(session.flow_count).unwrap_or(i64::MAX))
        .bind(&session.notes)
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn get_by_id(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        let row = sqlx::query(
            "SELECT id, name, target_host, start_time, end_time, flow_count, notes
             FROM sessions
             WHERE id = ?",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?;
        row.as_ref()
            .map(session_from_row)
            .transpose()
            .map_err(port_error)
    }
    async fn delete(&self, session_id: &str) -> Result<(), PortError> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(port_error)?;
        Ok(())
    }

    async fn clear_all(&self) -> Result<(), PortError> {
        sqlx::query("DELETE FROM sessions")
            .execute(&self.pool)
            .await
            .map_err(port_error)?;
        Ok(())
    }
}

impl SqliteSessionRepository {
    /// Most recent sessions, newest first. Used by the dashboard to list
    /// capture sessions.
    pub async fn list_recent(&self, limit: u64) -> Result<Vec<Session>, PortError> {
        let rows = sqlx::query(
            "SELECT id, name, target_host, start_time, end_time, flow_count, notes
             FROM sessions
             ORDER BY start_time DESC
             LIMIT ?",
        )
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(session_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }
}

#[async_trait]
impl WorkflowRepository for SqliteWorkflowRepository {
    async fn save_version(&self, version: &WorkflowVersion) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO workflow_versions (id, name, version, base_url, spec_json, status, created_at, approved_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 version = excluded.version,
                 base_url = excluded.base_url,
                 spec_json = excluded.spec_json,
                 status = excluded.status,
                 approved_at = excluded.approved_at",
        )
        .bind(&version.id)
        .bind(&version.name)
        .bind(version.version)
        .bind(&version.base_url)
        .bind(&version.spec_json)
        .bind(&version.status)
        .bind(version.created_at.to_rfc3339())
        .bind(version.approved_at.map(|time| time.to_rfc3339()))
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn get_version(&self, id: &str) -> Result<Option<WorkflowVersion>, PortError> {
        let row = sqlx::query(
            "SELECT id, name, version, base_url, spec_json, status, created_at, approved_at
             FROM workflow_versions
             WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?;
        row.as_ref()
            .map(workflow_version_from_row)
            .transpose()
            .map_err(port_error)
    }

    async fn list_versions(&self) -> Result<Vec<WorkflowVersion>, PortError> {
        let rows = sqlx::query(
            "SELECT id, name, version, base_url, spec_json, status, created_at, approved_at
             FROM workflow_versions
             ORDER BY created_at DESC
             LIMIT 200",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(workflow_version_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }

    async fn save_run(&self, run: &WorkflowRun) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO workflow_runs (run_id, workflow_id, started_at, finished_at, status, results_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(run_id) DO UPDATE SET
                 workflow_id = excluded.workflow_id,
                 started_at = excluded.started_at,
                 finished_at = excluded.finished_at,
                 status = excluded.status,
                 results_json = excluded.results_json",
        )
        .bind(&run.run_id)
        .bind(&run.version_id)
        .bind(run.started_at.to_rfc3339())
        .bind(run.finished_at.map(|time| time.to_rfc3339()))
        .bind(&run.status)
        .bind(&run.results_json)
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn update_run(
        &self,
        run_id: &str,
        status: &str,
        finished_at: Option<DateTime<Utc>>,
        results_json: &str,
    ) -> Result<(), PortError> {
        sqlx::query(
            "UPDATE workflow_runs SET status = ?, finished_at = ?, results_json = ? WHERE run_id = ?",
        )
        .bind(status)
        .bind(finished_at.map(|time| time.to_rfc3339()))
        .bind(results_json)
        .bind(run_id)
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn get_run(&self, run_id: &str) -> Result<Option<WorkflowRun>, PortError> {
        let row = sqlx::query(
            "SELECT run_id, workflow_id, started_at, finished_at, status, results_json
             FROM workflow_runs
             WHERE run_id = ?",
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?;
        row.as_ref()
            .map(workflow_run_from_row)
            .transpose()
            .map_err(port_error)
    }

    async fn list_runs(&self, version_id: &str) -> Result<Vec<WorkflowRun>, PortError> {
        let rows = sqlx::query(
            "SELECT run_id, workflow_id, started_at, finished_at, status, results_json
             FROM workflow_runs
             WHERE workflow_id = ?
             ORDER BY started_at DESC
             LIMIT 100",
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(workflow_run_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }
}

fn workflow_version_from_row(row: &SqliteRow) -> Result<WorkflowVersion, sqlx::Error> {
    let approved_at: Option<String> = row.try_get("approved_at")?;
    Ok(WorkflowVersion {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        version: row.try_get("version")?,
        base_url: row.try_get("base_url")?,
        spec_json: row.try_get("spec_json")?,
        status: row.try_get("status")?,
        created_at: parse_timestamp(&row.try_get::<String, _>("created_at")?)?,
        approved_at: approved_at.as_deref().map(parse_timestamp).transpose()?,
    })
}

fn workflow_run_from_row(row: &SqliteRow) -> Result<WorkflowRun, sqlx::Error> {
    let finished_at: Option<String> = row.try_get("finished_at")?;
    Ok(WorkflowRun {
        run_id: row.try_get("run_id")?,
        version_id: row.try_get("workflow_id")?,
        started_at: parse_timestamp(&row.try_get::<String, _>("started_at")?)?,
        finished_at: finished_at.as_deref().map(parse_timestamp).transpose()?,
        status: row.try_get("status")?,
        results_json: row.try_get("results_json")?,
    })
}

#[async_trait]
impl SecurityRepository for SqliteSecurityRepository {
    async fn save_plan(&self, plan: &SecurityPlan) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO security_plans (id, name, base_url, plan_json, status, created_at, approved_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 base_url = excluded.base_url,
                 plan_json = excluded.plan_json,
                 status = excluded.status,
                 approved_at = excluded.approved_at",
        )
        .bind(&plan.id)
        .bind(&plan.name)
        .bind(&plan.base_url)
        .bind(&plan.plan_json)
        .bind(&plan.status)
        .bind(plan.created_at.to_rfc3339())
        .bind(plan.approved_at.map(|t| t.to_rfc3339()))
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn get_plan(&self, id: &str) -> Result<Option<SecurityPlan>, PortError> {
        let row = sqlx::query(
            "SELECT id, name, base_url, plan_json, status, created_at, approved_at FROM security_plans WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?;
        row.as_ref()
            .map(security_plan_from_row)
            .transpose()
            .map_err(port_error)
    }

    async fn list_plans(&self) -> Result<Vec<SecurityPlan>, PortError> {
        let rows = sqlx::query(
            "SELECT id, name, base_url, plan_json, status, created_at, approved_at FROM security_plans ORDER BY created_at DESC LIMIT 200",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(security_plan_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }

    async fn save_run(&self, run: &SecurityRun) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO security_runs (run_id, plan_id, started_at, finished_at, status, findings_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(run_id) DO UPDATE SET
                 plan_id = excluded.plan_id,
                 started_at = excluded.started_at,
                 finished_at = excluded.finished_at,
                 status = excluded.status,
                 findings_json = excluded.findings_json",
        )
        .bind(&run.run_id)
        .bind(&run.plan_id)
        .bind(run.started_at.to_rfc3339())
        .bind(run.finished_at.map(|t| t.to_rfc3339()))
        .bind(&run.status)
        .bind(&run.findings_json)
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn update_run(
        &self,
        run_id: &str,
        status: &str,
        finished_at: Option<DateTime<Utc>>,
        findings_json: &str,
    ) -> Result<(), PortError> {
        sqlx::query(
            "UPDATE security_runs SET status = ?, finished_at = ?, findings_json = ? WHERE run_id = ?",
        )
        .bind(status)
        .bind(finished_at.map(|t| t.to_rfc3339()))
        .bind(findings_json)
        .bind(run_id)
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn get_run(&self, run_id: &str) -> Result<Option<SecurityRun>, PortError> {
        let row = sqlx::query(
            "SELECT run_id, plan_id, started_at, finished_at, status, findings_json FROM security_runs WHERE run_id = ?",
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?;
        row.as_ref()
            .map(security_run_from_row)
            .transpose()
            .map_err(port_error)
    }

    async fn list_runs(&self, plan_id: &str) -> Result<Vec<SecurityRun>, PortError> {
        let rows = sqlx::query(
            "SELECT run_id, plan_id, started_at, finished_at, status, findings_json FROM security_runs WHERE plan_id = ? ORDER BY started_at DESC LIMIT 100",
        )
        .bind(plan_id)
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(security_run_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }
}

#[async_trait]
impl AnnotationRepository for SqliteAnnotationRepository {
    async fn upsert(&self, annotation: &SitemapAnnotation) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO sitemap_annotations (key, comment, color, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET
                 comment = excluded.comment,
                 color = excluded.color,
                 updated_at = excluded.updated_at",
        )
        .bind(&annotation.key)
        .bind(&annotation.comment)
        .bind(&annotation.color)
        .bind(annotation.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), PortError> {
        sqlx::query("DELETE FROM sitemap_annotations WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(port_error)?;
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<SitemapAnnotation>, PortError> {
        let rows = sqlx::query(
            "SELECT key, comment, color, updated_at FROM sitemap_annotations ORDER BY updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(port_error)?;
        rows.iter()
            .map(|row| {
                Ok(SitemapAnnotation {
                    key: row.try_get("key")?,
                    comment: row.try_get("comment")?,
                    color: row.try_get("color")?,
                    updated_at: parse_timestamp(&row.try_get::<String, _>("updated_at")?)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(port_error)
    }
}

fn security_plan_from_row(row: &SqliteRow) -> Result<SecurityPlan, sqlx::Error> {
    let approved_at: Option<String> = row.try_get("approved_at")?;
    Ok(SecurityPlan {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        base_url: row.try_get("base_url")?,
        plan_json: row.try_get("plan_json")?,
        status: row.try_get("status")?,
        created_at: parse_timestamp(&row.try_get::<String, _>("created_at")?)?,
        approved_at: approved_at.as_deref().map(parse_timestamp).transpose()?,
    })
}

fn security_run_from_row(row: &SqliteRow) -> Result<SecurityRun, sqlx::Error> {
    let finished_at: Option<String> = row.try_get("finished_at")?;
    Ok(SecurityRun {
        run_id: row.try_get("run_id")?,
        plan_id: row.try_get("plan_id")?,
        started_at: parse_timestamp(&row.try_get::<String, _>("started_at")?)?,
        finished_at: finished_at.as_deref().map(parse_timestamp).transpose()?,
        status: row.try_get("status")?,
        findings_json: row.try_get("findings_json")?,
    })
}

const SELECT_FLOW: &str = "SELECT id, session_id, timestamp, method, host, ip, path, full_url,
                    request_headers, request_body, request_cookies, request_cookie_values,
                    response_status, response_headers, response_body, response_cookies,
                    response_cookie_values, content_type
             FROM flows
             WHERE id = ?";

fn flow_from_row(row: &SqliteRow) -> Result<HttpFlow, sqlx::Error> {
    let timestamp = parse_timestamp(&row.try_get::<String, _>("timestamp")?)?;
    let response_body: Option<String> = row.try_get("response_body")?;
    Ok(HttpFlow {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        timestamp,
        method: parse_method(&row.try_get::<String, _>("method")?)?,
        host: row.try_get("host")?,
        ip: row.try_get("ip")?,
        path: row.try_get("path")?,
        full_url: row.try_get("full_url")?,
        request_headers: decode_map(&row.try_get::<String, _>("request_headers")?)?,
        request_body: row.try_get("request_body")?,
        request_cookies: decode_vec(&row.try_get::<String, _>("request_cookies")?)?,
        request_cookie_values: decode_map(&row.try_get::<String, _>("request_cookie_values")?)?,
        response_status: u16::try_from(row.try_get::<i64, _>("response_status")?).unwrap_or(0),
        response_headers: decode_map(&row.try_get::<String, _>("response_headers")?)?,
        response_body: response_body.clone(),
        response_body_len: response_body.as_deref().map_or(0, str::len),
        response_cookies: decode_vec(&row.try_get::<String, _>("response_cookies")?)?,
        response_cookie_values: decode_map(&row.try_get::<String, _>("response_cookie_values")?)?,
        content_type: row.try_get("content_type")?,
        duration_ms: 0,
    })
}

/// Builds a summary-only flow (no bodies/headers) from a meta row. The
/// `response_body_len` column is `LENGTH(response_body)` computed in SQL.
fn flow_meta_from_row(row: &SqliteRow) -> Result<HttpFlow, sqlx::Error> {
    let timestamp = parse_timestamp(&row.try_get::<String, _>("timestamp")?)?;
    Ok(HttpFlow {
        id: row.try_get("id")?,
        session_id: row.try_get("session_id")?,
        timestamp,
        method: parse_method(&row.try_get::<String, _>("method")?)?,
        host: row.try_get("host")?,
        ip: row.try_get("ip")?,
        path: row.try_get("path")?,
        full_url: row.try_get("full_url")?,
        request_headers: std::collections::BTreeMap::new(),
        request_body: None,
        request_cookies: decode_vec(&row.try_get::<String, _>("request_cookies")?)?,
        request_cookie_values: decode_map(&row.try_get::<String, _>("request_cookie_values")?)?,
        response_status: u16::try_from(row.try_get::<i64, _>("response_status")?).unwrap_or(0),
        response_headers: std::collections::BTreeMap::new(),
        response_body: None,
        response_body_len: usize::try_from(row.try_get::<i64, _>("response_body_len")?)
            .unwrap_or(0),
        response_cookies: decode_vec(&row.try_get::<String, _>("response_cookies")?)?,
        response_cookie_values: decode_map(&row.try_get::<String, _>("response_cookie_values")?)?,
        content_type: row.try_get("content_type")?,
        duration_ms: 0,
    })
}

fn session_from_row(row: &SqliteRow) -> Result<Session, sqlx::Error> {
    let end_time: Option<String> = row.try_get("end_time")?;
    Ok(Session {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        target_host: row.try_get("target_host")?,
        start_time: parse_timestamp(&row.try_get::<String, _>("start_time")?)?,
        end_time: end_time.as_deref().map(parse_timestamp).transpose()?,
        flow_count: u64::try_from(row.try_get::<i64, _>("flow_count")?).unwrap_or(0),
        notes: row.try_get("notes")?,
    })
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, sqlx::Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(decode_error)
}

fn parse_method(value: &str) -> Result<HttpMethod, sqlx::Error> {
    match value {
        "GET" => Ok(HttpMethod::Get),
        "POST" => Ok(HttpMethod::Post),
        "PUT" => Ok(HttpMethod::Put),
        "DELETE" => Ok(HttpMethod::Delete),
        "PATCH" => Ok(HttpMethod::Patch),
        "OPTIONS" => Ok(HttpMethod::Options),
        "HEAD" => Ok(HttpMethod::Head),
        other => Ok(HttpMethod::Other(other.to_owned())),
    }
}

fn decode_map(value: &str) -> Result<std::collections::BTreeMap<String, String>, sqlx::Error> {
    serde_json::from_str(value).map_err(decode_error)
}

fn decode_vec(value: &str) -> Result<Vec<String>, sqlx::Error> {
    serde_json::from_str(value).map_err(decode_error)
}

fn decode_error(error: impl std::fmt::Display) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    )))
}

fn storage_error(error: serde_json::Error) -> PortError {
    PortError::Permanent(format!("serialization error: {error}"))
}

fn port_error(error: sqlx::Error) -> PortError {
    if is_readonly_error(&error) {
        PortError::Permanent(format!(
            "{error} — database is read-only: another instance may be running, \
             or stale -wal/-shm files are locked; restarting the app clears this"
        ))
    } else if is_transient_error(&error) {
        PortError::Transient(error.to_string())
    } else {
        PortError::Permanent(error.to_string())
    }
}

/// True for SQLite primary code 8 (SQLITE_READONLY): the file opens and reads
/// but every write fails, typically from stale WAL/SHM side files left by a
/// force-killed process or a second instance holding the same database.
fn is_readonly_error(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(database_error) = error else {
        return false;
    };
    let message = database_error.message().to_lowercase();
    database_error
        .code()
        .and_then(|code| code.parse::<i32>().ok())
        .map(|code| code & 0xFF)
        == Some(8)
        || message.contains("readonly")
        || message.contains("read-only")
}

fn is_readonly_storage_error(error: &StorageError) -> bool {
    match error {
        StorageError::Sqlx(inner) => is_readonly_error(inner),
        StorageError::Connect(message) => {
            let m = message.to_lowercase();
            m.contains("readonly") || m.contains("read-only") || m.contains("readonly database")
        }
        _ => false,
    }
}

fn is_transient_error(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database_error) => {
            // SQLite primary result codes: SQLITE_BUSY = 5, SQLITE_LOCKED = 6.
            let primary = database_error
                .code()
                .and_then(|code| code.parse::<i32>().ok())
                .map(|code| code & 0xFF)
                .unwrap_or(0);
            primary == 5 || primary == 6
        }
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => true,
        _ => false,
    }
}
