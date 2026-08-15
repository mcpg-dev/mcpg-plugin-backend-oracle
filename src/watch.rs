//! `watch_strategy` entity (`oracle_poll`) — the POLLING change-watch path.
//!
//! Oracle has no native change-push channel here, so this strategy polls a cheap
//! read-only scalar "high-water" query (`SELECT max(updated_at) FROM events`,
//! `SELECT count(*) FROM …`, a monotonic sequence, …) on a cadence and signals a
//! change whenever that scalar advances. The poll thread, the cursor diff, the
//! stop signal and the opaque handle round-trip all live in the shared
//! [`mcpg_plugin_sdk::watch`] helper — this entity only supplies the per-tick
//! `poll` closure over its own connection.
//!
//! rust-oracle is synchronous and dlopen-bound, while the `deadpool` pool's
//! `get()` is async. The helper's loop is synchronous and runs the closure on
//! its own dedicated OS thread, so a single current-thread tokio runtime is
//! built once in [`watch`] and moved into the closure; each tick `block_on`s the
//! `pool.get()` + `spawn_blocking(run_statement_blocking)` chain (sequential
//! ticks, so a single-thread runtime is enough). Connect / query failures map to
//! the closure's `Err(String)` — the helper logs and retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::Value;

use crate::oracle::{OracleManager, QueryOutcome, build_pool, run_statement_blocking};
use crate::types::OracleOp;

pub const PLUGIN_ID: &str = "dev.mcpg.backend.oracle";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "oracle_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick query budget when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

/// Reject a tracking query that is not read-only. Delegates to the shared
/// hardened SQL guard, which enforces a read-only leading keyword AND rejects
/// write/DDL keywords anywhere (write-CTEs), `EXPLAIN ANALYZE`, and stacked
/// statements.
pub(crate) fn enforce_read_only(statement: &str) -> Result<(), String> {
    mcpg_plugin_sdk::sql_guard::enforce_read_only(statement)
}

/// Per-watch spec: the Oracle connection fields needed to open a session
/// (reusing the backend's connection shape — `dsn` / `username` / `password`)
/// plus the read-only scalar high-water `tracking_query` and the poll cadence.
/// The connection is carried per-watch (not at plugin level), so a watcher is
/// self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// Oracle data source name — an Easy Connect string (`//host:1521/SERVICE`)
    /// or a TNS alias. Operator-configured. REQUIRED.
    dsn: String,
    /// Database username. REQUIRED.
    username: String,
    /// Login password. A literal, or a `${env.X}` / `vault://...` reference the
    /// gateway secret-resolver expands at config load — never plaintext in
    /// committed config. REQUIRED.
    password: String,
    /// The read-only scalar high-water query whose first-row first-column value
    /// is the cursor (e.g. `SELECT max(updated_at) FROM events`). REQUIRED.
    tracking_query: String,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick connect + statement + read budget in milliseconds
    /// (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + tracking query arrive on the per-watch spec.
pub struct OracleWatchCdylib {
    manifest: PluginManifest,
}

impl OracleWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + `tracking_query` arrive
    /// via the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.oracle",
                name: "Oracle Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Extract the cursor scalar from a high-water query outcome: the first column
/// of the first row, stringified. `None` when the query returned zero rows (no
/// signal this tick), the first row has no columns, or the scalar is SQL NULL.
/// String values yield the bare string; everything else its JSON rendering, so
/// the cursor comparison is stable across ticks.
fn cursor_from_outcome(outcome: &QueryOutcome) -> Option<String> {
    let rows = outcome.rows.as_ref()?;
    let first = rows.first()?;
    let scalar = first.as_object()?.values().next()?;
    Some(match scalar {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    })
}

impl SyncWatchStrategyPlugin for OracleWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid oracle_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.dsn.trim().is_empty() {
            return Err(invalid("dsn must not be empty".into()));
        }
        if parsed.username.trim().is_empty() {
            return Err(invalid("username must not be empty".into()));
        }
        if parsed.tracking_query.trim().is_empty() {
            return Err(invalid("tracking_query must not be empty".into()));
        }
        // Per-caller `cred://` is unsupported (the connection is one service
        // identity), matching the backend register guard.
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are \
                 unsupported (the connection is one service identity); use ${env.X} / \
                 vault:// (resolved at config load) instead"
                    .into(),
            ));
        }
        // The tracking query is read-only by contract — fence it so a polling
        // watcher can never mutate the server.
        enforce_read_only(&parsed.tracking_query).map_err(invalid)?;

        // One current-thread runtime, moved into the closure: ticks are
        // sequential, so a single-thread runtime is enough to `block_on` the
        // async `pool.get()` + the per-tick `spawn_blocking` statement chain.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("oracle_poll: tokio runtime init failed: {e}"),
            })?;

        // Lazy single-connection pool — no ODPI-C call happens here (no socket
        // opened until the first `pool.get()` on the first tick). A failure to
        // build the pool config maps to a subscribe error.
        let manager = OracleManager::new(parsed.username, parsed.password, parsed.dsn);
        let pool = build_pool(manager, 1).map_err(|e| WatchError::Subscribe {
            message: format!("oracle_poll: pool build failed: {e}"),
        })?;
        let pool = Arc::new(pool);

        let tracking_query = Arc::new(parsed.tracking_query);
        let timeout = Duration::from_millis(parsed.timeout_ms);

        let poll = move || -> Result<Option<String>, String> {
            let pool = Arc::clone(&pool);
            let tracking_query = Arc::clone(&tracking_query);
            let outcome = rt.block_on(async move {
                let conn = match tokio::time::timeout(timeout, pool.get()).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => return Err(format!("Oracle pool acquire failed: {e}")),
                    Err(_) => return Err("Oracle pool acquire timed out".to_owned()),
                };
                let sql = (*tracking_query).clone();
                let blocking = tokio::task::spawn_blocking(move || {
                    run_statement_blocking(&conn, &sql, Vec::new(), OracleOp::Query, 1, timeout)
                });
                match tokio::time::timeout(timeout, blocking).await {
                    Ok(Ok(inner)) => inner,
                    Ok(Err(join_err)) => Err(format!("Oracle worker task failed: {join_err}")),
                    Err(_) => Err("Oracle call timed out".to_owned()),
                }
            })?;
            Ok(cursor_from_outcome(&outcome))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(parsed.interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> OracleWatchCdylib {
        OracleWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "tracking_query": "SELECT max(updated_at) FROM events",
        }))
        .unwrap();
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
    }

    #[test]
    fn spec_parses_overrides() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "dsn": "//db:1521/S",
            "username": "reader",
            "password": "pw",
            "tracking_query": "SELECT count(*) FROM events",
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "oracle://events",
                &json!({
                    "dsn": "//db:1521/S",
                    "username": "u",
                    "password": "p",
                    "tracking_query": "SELECT 1 FROM dual",
                    "bogus": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_tracking_query_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "oracle://events",
                &json!({
                    "dsn": "//db:1521/S",
                    "username": "u",
                    "password": "p",
                    "tracking_query": "   ",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn non_read_only_tracking_query_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "oracle://events",
                &json!({
                    "dsn": "//db:1521/S",
                    "username": "u",
                    "password": "p",
                    "tracking_query": "DELETE FROM events",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cred_password_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "oracle://events",
                &json!({
                    "dsn": "//db:1521/S",
                    "username": "u",
                    "password": "cred://vault/oracle",
                    "tracking_query": "SELECT max(t) FROM e",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn read_only_guard_allows_select_and_with() {
        assert!(enforce_read_only("SELECT max(t) FROM e").is_ok());
        assert!(enforce_read_only("  with cte as (select 1 from dual) select * from cte").is_ok());
        assert!(enforce_read_only("/* c */ -- l\nSELECT 1 FROM dual").is_ok());
    }

    #[test]
    fn read_only_guard_rejects_writes_and_ddl() {
        for s in [
            "INSERT INTO e VALUES (1)",
            "UPDATE e SET v = 1",
            "DELETE FROM e",
            "MERGE INTO e ...",
            "BEGIN null; END;",
            "   ",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
    }

    #[test]
    fn read_only_guard_delegates_to_hardened_sdk_guard() {
        // The shared guard rejects write-CTEs, EXPLAIN ANALYZE, and stacked
        // statements that the old leading-keyword-only check let through.
        assert!(enforce_read_only("WITH x AS (INSERT INTO t SELECT 1) SELECT * FROM x").is_err());
        assert!(enforce_read_only("EXPLAIN ANALYZE SELECT 1").is_err());
        assert!(enforce_read_only("SELECT 1; DROP TABLE t").is_err());
        // A plain read still passes.
        assert!(enforce_read_only("SELECT 1").is_ok());
    }

    #[test]
    fn cursor_from_outcome_extracts_first_scalar() {
        let outcome = QueryOutcome {
            rows: Some(vec![json!({ "MAX(UPDATED_AT)": "2026-06-23 10:00:00" })]),
            rows_affected: None,
        };
        assert_eq!(
            cursor_from_outcome(&outcome).as_deref(),
            Some("2026-06-23 10:00:00")
        );

        let outcome = QueryOutcome {
            rows: Some(vec![json!({ "COUNT(*)": 42 })]),
            rows_affected: None,
        };
        assert_eq!(cursor_from_outcome(&outcome).as_deref(), Some("42"));
    }

    #[test]
    fn cursor_from_outcome_none_on_zero_rows_or_null() {
        let empty = QueryOutcome {
            rows: Some(vec![]),
            rows_affected: None,
        };
        assert_eq!(cursor_from_outcome(&empty), None);

        let no_rows = QueryOutcome {
            rows: None,
            rows_affected: Some(0),
        };
        assert_eq!(cursor_from_outcome(&no_rows), None);

        let null = QueryOutcome {
            rows: Some(vec![json!({ "MAX(T)": Value::Null })]),
            rows_affected: None,
        };
        assert_eq!(cursor_from_outcome(&null), None);
    }
}
