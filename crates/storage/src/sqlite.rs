use std::str::FromStr;

use api_tester_domain::{HttpFlow, HttpMethod, Session};
use api_tester_ports::{FlowRepository, PortError, SessionRepository};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
}

#[derive(Clone)]
pub struct SqliteFlowRepository {
    pool: Pool<Sqlite>,
}

#[derive(Clone)]
pub struct SqliteSessionRepository {
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

        Ok(Self {
            pool: pool.clone(),
            flows: SqliteFlowRepository { pool: pool.clone() },
            sessions: SqliteSessionRepository { pool },
        })
    }

    pub fn flows(&self) -> &SqliteFlowRepository {
        &self.flows
    }

    pub fn sessions(&self) -> &SqliteSessionRepository {
        &self.sessions
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

const SELECT_FLOW: &str = "SELECT id, session_id, timestamp, method, host, ip, path, full_url,
                    request_headers, request_body, request_cookies, request_cookie_values,
                    response_status, response_headers, response_body, response_cookies,
                    response_cookie_values, content_type
             FROM flows
             WHERE id = ?";

fn flow_from_row(row: &SqliteRow) -> Result<HttpFlow, sqlx::Error> {
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
        request_headers: decode_map(&row.try_get::<String, _>("request_headers")?)?,
        request_body: row.try_get("request_body")?,
        request_cookies: decode_vec(&row.try_get::<String, _>("request_cookies")?)?,
        request_cookie_values: decode_map(&row.try_get::<String, _>("request_cookie_values")?)?,
        response_status: u16::try_from(row.try_get::<i64, _>("response_status")?).unwrap_or(0),
        response_headers: decode_map(&row.try_get::<String, _>("response_headers")?)?,
        response_body: row.try_get("response_body")?,
        response_cookies: decode_vec(&row.try_get::<String, _>("response_cookies")?)?,
        response_cookie_values: decode_map(&row.try_get::<String, _>("response_cookie_values")?)?,
        content_type: row.try_get("content_type")?,
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
    if is_transient_error(&error) {
        PortError::Transient(error.to_string())
    } else {
        PortError::Permanent(error.to_string())
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
