//! Oracle/ODPI-C machinery: a lazy pooled blocking statement runner and
//! row → JSON projection.
//!
//! rust-oracle is synchronous and dlopen's the Oracle Client (`libclntsh`) at
//! runtime, so every Oracle call here runs inside a `spawn_blocking` closure
//! (see `lib.rs`). `oracle::Connection` is `Send + Sync` (the crate asserts
//! both at compile time), so connections are pooled with `deadpool`: the
//! [`OracleManager`] opens / pings sessions inside `spawn_blocking`, and the
//! pooled [`Object`] is moved into the per-call `spawn_blocking` to run the
//! statement. The pool is built lazily at `register_profile` and opens NO
//! connection until the first `pool.get()`, so register and the unit tests stay
//! free of any ODPI-C call (no Instant Client needed to compile or unit-test).

use std::time::Duration;

use base64::Engine as _;
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use oracle::Connection;
use oracle::sql_type::{OracleType, ToSql};
use serde_json::{Map, Value};

use crate::params::OracleBind;
use crate::types::OracleOp;

/// Result of a completed statement — rows (query) xor a count (execute).
pub struct QueryOutcome {
    pub rows: Option<Vec<Value>>,
    pub rows_affected: Option<u64>,
}

/// deadpool manager that opens rust-oracle / ODPI-C sessions. `create` and
/// `recycle` run the blocking ODPI-C calls on a blocking thread so they never
/// stall the async runtime. The connection's per-call timeout is (re)applied in
/// the per-call runner, not here, so it always reflects the live request.
pub struct OracleManager {
    username: String,
    password: String,
    dsn: String,
}

impl OracleManager {
    #[must_use]
    pub fn new(username: String, password: String, dsn: String) -> Self {
        Self {
            username,
            password,
            dsn,
        }
    }
}

impl Manager for OracleManager {
    type Type = Connection;
    type Error = String;

    async fn create(&self) -> Result<Connection, String> {
        let username = self.username.clone();
        let password = self.password.clone();
        let dsn = self.dsn.clone();
        tokio::task::spawn_blocking(move || {
            Connection::connect(&username, &password, &dsn).map_err(|e| {
                mcpg_plugin_protocol::redact::redact_in_text(&format!(
                    "Oracle connect/login failed: {e}"
                ))
            })
        })
        .await
        .map_err(|e| format!("Oracle connect worker task failed: {e}"))?
    }

    async fn recycle(&self, conn: &mut Connection, _m: &Metrics) -> RecycleResult<String> {
        // Cheap round-trip to confirm the pooled session is still live before
        // it is handed back out. ODPI-C is synchronous and takes only a `&self`
        // borrow here; `spawn_blocking` needs a `'static` value, and the pool
        // only lends `&mut Connection`, so this single sub-millisecond ping runs
        // inline on the recycle path (it is not a per-call statement). A failed
        // ping evicts the connection and the pool opens a fresh one.
        conn.query_row("SELECT 1 FROM dual", &[])
            .map(|_| ())
            .map_err(|e| RecycleError::Backend(format!("recycle ping failed: {e}")))
    }
}

/// Pool alias for one binding.
pub type OraclePool = Pool<OracleManager>;

/// Build a per-binding connection pool. This is LAZY — no connection is opened
/// until the first `pool.get()`, so it is safe to call from `register_profile`
/// without an Oracle Instant Client.
pub fn build_pool(manager: OracleManager, max_size: usize) -> Result<OraclePool, String> {
    Pool::builder(manager)
        .max_size(max_size)
        .build()
        .map_err(|e| format!("Oracle pool build failed: {e}"))
}

/// Box one bind value as a `dyn ToSql`. Bool binds as a 0/1 integer — Oracle
/// before 23c has no SQL BOOLEAN type; a NULL binds as a typed NULL string.
fn bind_box(value: &OracleBind) -> Box<dyn ToSql> {
    match value {
        OracleBind::Null => Box::new(None::<String>),
        OracleBind::Int(i) => Box::new(*i),
        OracleBind::Float(f) => Box::new(*f),
        OracleBind::Bool(b) => Box::new(i32::from(*b)),
        OracleBind::Str(s) => Box::new(s.clone()),
    }
}

/// Set the call timeout on the pooled connection and run the statement.
/// Blocking — call from `spawn_blocking` with a pooled connection. Call-timeout
/// / statement failures return `Err`. The connection is borrowed (`&conn`), so
/// it drops back to the pool when the caller drops the pooled object.
pub fn run_statement_blocking(
    conn: &Connection,
    query_sql: &str,
    bound: Vec<OracleBind>,
    op: OracleOp,
    size_limit: usize,
    timeout: Duration,
) -> Result<QueryOutcome, String> {
    // Bound the DB round-trip itself (ODPI-C call timeout), in addition to the
    // outer tokio timeout on the whole blocking task. Re-applied per call so it
    // always reflects the live request's deadline even on a reused connection.
    conn.set_call_timeout(Some(timeout))
        .map_err(|e| format!("Oracle set_call_timeout failed: {e}"))?;

    let boxes: Vec<Box<dyn ToSql>> = bound.iter().map(bind_box).collect();
    let param_refs: Vec<&dyn ToSql> = boxes.iter().map(AsRef::as_ref).collect();

    match op {
        OracleOp::Query => {
            let result_set = conn
                .query(query_sql, &param_refs)
                .map_err(|e| format!("Oracle query failed: {e}"))?;
            // Column names + types are stable for the whole result set.
            let columns: Vec<(String, OracleType)> = result_set
                .column_info()
                .iter()
                .map(|ci| (ci.name().to_owned(), ci.oracle_type().clone()))
                .collect();
            let mut rows = Vec::new();
            for row_result in result_set.take(size_limit) {
                let row = row_result.map_err(|e| format!("Oracle row read failed: {e}"))?;
                rows.push(row_to_json(&row, &columns));
            }
            Ok(QueryOutcome {
                rows: Some(rows),
                rows_affected: None,
            })
        }
        OracleOp::Execute => {
            let stmt = conn
                .execute(query_sql, &param_refs)
                .map_err(|e| format!("Oracle execute failed: {e}"))?;
            let n = stmt
                .row_count()
                .map_err(|e| format!("Oracle row_count failed: {e}"))?;
            // rust-oracle autocommit is off by default — commit explicitly.
            conn.commit()
                .map_err(|e| format!("Oracle commit failed: {e}"))?;
            Ok(QueryOutcome {
                rows: None,
                rows_affected: Some(n),
            })
        }
    }
}

/// One row → `{ column: value, … }`, projected by the column's `OracleType`.
/// Column names stay as the server reports them; duplicate names collapse
/// (last wins) — alias them in the query.
fn row_to_json(row: &oracle::Row, columns: &[(String, OracleType)]) -> Value {
    let mut obj = Map::new();
    for (i, (name, ora_type)) in columns.iter().enumerate() {
        obj.insert(name.clone(), column_to_json(row, i, ora_type));
    }
    Value::Object(obj)
}

/// Project column `i` to JSON by its Oracle type. Every `row.get` is fallible;
/// on any conversion error we fall back to a string read, then to JSON null,
/// so one odd value can never panic the marshaller. NULL of any type → null.
fn column_to_json(row: &oracle::Row, i: usize, ora_type: &OracleType) -> Value {
    match ora_type {
        // Numeric: try i64, then f64; a NUMBER too big for either is read as a
        // string to avoid precision loss, then emitted as a JSON string.
        OracleType::Number(..)
        | OracleType::Float(_)
        | OracleType::BinaryFloat
        | OracleType::BinaryDouble
        | OracleType::Int64
        | OracleType::UInt64 => number_to_json(row, i),
        // Text types.
        OracleType::Varchar2(_)
        | OracleType::NVarchar2(_)
        | OracleType::Char(_)
        | OracleType::NChar(_)
        | OracleType::Long
        | OracleType::CLOB
        | OracleType::NCLOB
        | OracleType::Rowid => string_to_json(row, i),
        // Temporal types: Oracle's default string rendering is acceptable.
        OracleType::Date
        | OracleType::Timestamp(_)
        | OracleType::TimestampTZ(_)
        | OracleType::TimestampLTZ(_)
        | OracleType::IntervalDS(..)
        | OracleType::IntervalYM(_) => string_to_json(row, i),
        // Binary types → base64.
        OracleType::Raw(_) | OracleType::LongRaw | OracleType::BLOB | OracleType::BFILE => {
            bytes_to_json(row, i)
        }
        // 23c native boolean.
        OracleType::Boolean => match row.get::<usize, Option<bool>>(i) {
            Ok(Some(b)) => Value::Bool(b),
            Ok(None) => Value::Null,
            Err(_) => string_to_json(row, i),
        },
        // JSON / XML / anything else: stringify, falling back to null.
        _ => string_to_json(row, i),
    }
}

fn number_to_json(row: &oracle::Row, i: usize) -> Value {
    if let Ok(opt) = row.get::<usize, Option<i64>>(i) {
        return match opt {
            Some(v) => Value::Number(v.into()),
            None => Value::Null,
        };
    }
    if let Ok(Some(f)) = row.get::<usize, Option<f64>>(i)
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        return Value::Number(n);
    }
    // Out-of-range / high-precision NUMBER: keep full fidelity as a string.
    string_to_json(row, i)
}

fn string_to_json(row: &oracle::Row, i: usize) -> Value {
    match row.get::<usize, Option<String>>(i) {
        Ok(Some(s)) => Value::String(s),
        Ok(None) => Value::Null,
        Err(_) => Value::Null,
    }
}

fn bytes_to_json(row: &oracle::Row, i: usize) -> Value {
    match row.get::<usize, Option<Vec<u8>>>(i) {
        Ok(Some(b)) => Value::String(base64::engine::general_purpose::STANDARD.encode(b)),
        Ok(None) => Value::Null,
        // A BLOB/LONG-RAW that won't materialise as bytes falls back to string.
        Err(_) => string_to_json(row, i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The row marshaller can't be exercised without a live DB (rust-oracle
    // Rows aren't synthetically constructible), so it is covered by the
    // integration test. Here we only assert the connection-free bind boxing,
    // which must not touch ODPI-C.
    #[test]
    fn bind_box_covers_all_scalars() {
        let _ = bind_box(&OracleBind::Null);
        let _ = bind_box(&OracleBind::Int(7));
        let _ = bind_box(&OracleBind::Float(1.5));
        let _ = bind_box(&OracleBind::Bool(true));
        let _ = bind_box(&OracleBind::Str("x".into()));
    }
}
