//! Oracle Database backend binding plugin for mcpg.
//!
//! Implements [`OracleBackendPlugin`] — `BackendPlugin` for `kind: "oracle"`.
//! Runs a parameterised statement whose `:1, :2, …` placeholders are bound
//! from CEL expressions evaluated against the tool arguments (bound as SQL
//! parameters, never interpolated — injection-safe). `op: query` returns rows;
//! `op: execute` returns rows-affected. Structurally mirrors the mssql/soap/
//! ldap backends; Oracle-specific machinery lives in [`oracle`] + [`params`] +
//! [`envelope`]. rust-oracle is synchronous and dlopen's the Oracle Client at
//! runtime, so each call runs inside `spawn_blocking` over a lazily pooled
//! connection (see README). The `deadpool` pool is built at `register_profile`
//! but opens NO connection until the first call, so register never touches
//! ODPI-C (no Instant Client needed to compile / unit-test).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::ResourcePage;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

mod catalog;
/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
// The driver-facing module shadows the `oracle` crate name within this file;
// reach the crate via `::oracle` where needed (only in `oracle.rs`).
mod oracle;
mod params;
mod surface;
mod types;
/// Polling `watch_strategy` entity (kind `oracle_poll`).
pub mod watch;

use catalog::CatalogFilterConfig;
use envelope::{build_result_envelope, classify_error};
use oracle::{OracleManager, OraclePool, build_pool, run_statement_blocking};
use params::{CompiledParam, OracleBind, compile_params, evaluate_params, json_to_oracle_bind};
pub use types::{
    CompletionConfig as OracleCompletionConfig, ListQueryConfig as OracleListQueryConfig,
    ListQueryMode, OracleBackendSpec, OracleOp, OracleOperation, validate_completion,
    validate_list_query,
};
use watch::enforce_read_only;

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.oracle.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.oracle.request_failed"),
        "oracle_error" => Some("dev.mcpg.backend.oracle.query_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.oracle.request_failed"),
        _ => None,
    }
}

/// Reject a bare `cred://` URI in an operator-fixed string. Secrets reach the
/// server through `${cred://…}` resolved at config load (the login password); a
/// bare `cred://` left in a statement would be sent to Oracle verbatim, which is
/// always an operator mistake.
fn reject_bare_cred(field: &str, value: &str) -> Result<(), String> {
    if value.contains("cred://") {
        return Err(format!(
            "{field} must not contain a bare cred:// URI — use ${{cred://…}} (resolved at config load)"
        ));
    }
    Ok(())
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.oracle".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("Oracle plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

// ------------------------------------------------------------------ plugin

/// Per-binding Oracle runtime — a lazy connection pool + compiled statement.
/// The pool opens no connection until the first call (see [`oracle::
/// build_pool`]). `dsn` is retained for the result envelope's connection field.
/// Cheap to clone (pool + params behind `Arc`).
#[derive(Clone)]
struct OracleProfile {
    pool: Arc<OraclePool>,
    dsn: String,
    query: String,
    compiled_params: Arc<[CompiledParam]>,
    op: OracleOp,
    operation: OracleOperation,
    /// Data-dictionary filter config (static + per-call argument names). Only
    /// consulted for the `list_tables` / `list_columns` operations.
    catalog_filters: Arc<CatalogFilterConfig>,
    size_limit: usize,
    timeout: Duration,
    surface: surface::Surface,
    surface_uri: Option<String>,
    list_query: Option<OracleListQueryConfig>,
    /// Per-`{id}` single-row read statement for a `resource_templates[]`
    /// binding. Bound from the same `compiled_params` as `query`; when None the
    /// resource-read branch falls back to `query`.
    read_query: Option<String>,
    variable_completions: Arc<BTreeMap<String, OracleCompletionConfig>>,
}

/// `BackendPlugin` implementation for `kind: "oracle"`.
pub struct OracleBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, OracleProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for OracleBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.oracle",
                name: "Oracle Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit).
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_oracle_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_oracle_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("oracle-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("oracle-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::oracle::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope (param-eval failures), emit the triad, and
    /// return it as a normal payload — matching the mssql/soap/ldap backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &OracleProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.dsn,
            profile.op.as_str(),
            None,
            None,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }
}

impl std::fmt::Debug for OracleBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for OracleBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "oracle"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: OracleBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("Oracle binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.dsn.trim().is_empty() {
            return Err(invalid("dsn must not be empty".into()));
        }
        if parsed.username.trim().is_empty() {
            return Err(invalid("username must not be empty".into()));
        }
        // The `query` statement is required only for `operation: query`; the
        // catalog operations introspect `ALL_TABLES` / `ALL_TAB_COLUMNS` and
        // ignore it. `list_columns` needs a table to scope to (a static `table`
        // or a per-call `table_arg`); without either it would list the columns
        // of every visible table — almost never the intent.
        match parsed.operation {
            OracleOperation::Query => {
                // A resource_template binding may supply only `read_query` (the
                // per-`{id}` single-row read) and omit `query`; otherwise the
                // operator-fixed `query` statement is required.
                if parsed.query.trim().is_empty()
                    && parsed
                        .read_query
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(invalid(
                        "query must not be empty (or set `read_query` for a resource_template read binding)".into(),
                    ));
                }
            }
            OracleOperation::ListColumns => {
                if parsed
                    .table
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                    && parsed
                        .table_arg
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(invalid(
                        "operation: list_columns requires a `table` filter or a `table_arg` (the table whose columns to list)".into(),
                    ));
                }
            }
            OracleOperation::ListTables => {}
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if parsed.size_limit == 0 {
            return Err(invalid("size_limit must be greater than 0".into()));
        }
        if parsed.pool_max_size == 0 {
            return Err(invalid("pool_max_size must be greater than 0".into()));
        }
        // Per-caller `cred://` is unsupported (the connection is one service
        // identity). Point operators at the config secret-resolver.
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are \
                 unsupported (the connection is one service identity); use ${env.X} / \
                 vault:// (resolved at config load) instead"
                    .into(),
            ));
        }

        // Surface coherence: `uri` is only meaningful on the resource surface;
        // a static `uri` on a tool/prompt binding is a config mistake worth a
        // fail-closed rejection at register rather than a silent no-op.
        if parsed.uri.is_some() && parsed.surface != surface::Surface::Resource {
            return Err(invalid(format!(
                "`uri` is only valid with `surface: resource` (this binding is `surface: {}`)",
                parsed.surface.as_str()
            )));
        }
        if let Some(u) = &parsed.uri
            && u.trim().is_empty()
        {
            return Err(invalid("`uri` must not be empty".into()));
        }

        // `read_query` is the per-`{id}` single-row read for a resource_template
        // binding; it is operator-fixed, must be read-only (SELECT/WITH) since a
        // `resources/read` never mutates, and must not carry a bare cred://. It
        // only makes sense on the resource surface — fail-closed elsewhere so a
        // misplaced field is never a silent no-op.
        if let Some(rq) = &parsed.read_query {
            if rq.trim().is_empty() {
                return Err(invalid("`read_query` must not be empty".into()));
            }
            if parsed.surface != surface::Surface::Resource {
                return Err(invalid(format!(
                    "`read_query` is only valid with `surface: resource` (this binding is `surface: {}`)",
                    parsed.surface.as_str()
                )));
            }
            reject_bare_cred("read_query", rq).map_err(invalid)?;
            enforce_read_only(rq).map_err(invalid)?;
        }

        // Listing + completion are operator-fixed read surfaces; fail-closed at
        // register so misconfig never reaches a list / completion call.
        if let Some(lq) = &parsed.list_query {
            validate_list_query(lq).map_err(invalid)?;
        }
        for (name, cc) in &parsed.variable_completions {
            validate_completion(name, cc).map_err(invalid)?;
        }

        let compiled_params: Arc<[CompiledParam]> =
            compile_params(&parsed.params).map_err(invalid)?.into();

        // Build the lazy pool — no connection is opened here (no ODPI-C call),
        // so register stays I/O-free with no Instant Client.
        let manager = OracleManager::new(parsed.username, parsed.password, parsed.dsn.clone());
        let pool = build_pool(manager, parsed.pool_max_size).map_err(invalid)?;

        debug!(
            backend = %backend_name,
            dsn = %parsed.dsn,
            operation = parsed.operation.as_str(),
            op = parsed.op.as_str(),
            params = compiled_params.len(),
            "registered Oracle binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            OracleProfile {
                pool: Arc::new(pool),
                dsn: parsed.dsn,
                query: parsed.query,
                compiled_params,
                op: parsed.op,
                operation: parsed.operation,
                catalog_filters: Arc::new(CatalogFilterConfig {
                    owner: parsed.owner,
                    table: parsed.table,
                    owner_arg: parsed.owner_arg,
                    table_arg: parsed.table_arg,
                }),
                size_limit: parsed.size_limit,
                timeout: Duration::from_millis(parsed.timeout_ms),
                surface: parsed.surface,
                surface_uri: parsed.uri,
                list_query: parsed.list_query,
                read_query: parsed.read_query,
                variable_completions: Arc::new(parsed.variable_completions),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "oracle_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("Oracle plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // Catalog-introspection ops bypass CEL params entirely: they resolve the
        // (optionally caller-supplied) owner/table filters, build the
        // data-dictionary `SELECT`, and bind the filters as `:owner` / `:tbl`
        // parameters (never interpolated into SQL). They always run as a read
        // (`op: query`), independent of the binding's `op`.
        let result: Result<QueryOutcomeResult, String> = if profile.operation.is_catalog() {
            let filters = profile.catalog_filters.resolve(&arguments);
            let (sql, binds) = catalog::build_query(profile.operation, &filters);
            self.run_pooled(&profile, &sql, binds, OracleOp::Query, profile.size_limit)
                .await
                .map(QueryOutcomeResult)
        } else {
            // Evaluate the CEL parameter expressions, then lower each to a scalar
            // Oracle bind (rejecting arrays/objects) — all connection-free.
            let bound = match evaluate_params(&profile.compiled_params, &arguments) {
                Ok(values) => {
                    let mut binds: Vec<OracleBind> = Vec::with_capacity(values.len());
                    let mut err: Option<String> = None;
                    for v in values {
                        match json_to_oracle_bind(v) {
                            Ok(b) => binds.push(b),
                            Err(e) => {
                                err = Some(format!("binding params: {e}"));
                                break;
                            }
                        }
                    }
                    if let Some(message) = err {
                        return self
                            .finish_error(
                                &profile,
                                backend_name,
                                &tool_name,
                                &message,
                                "invalid_spec",
                                identity.as_ref(),
                                &request_id,
                                started,
                                host_span,
                            )
                            .await;
                    }
                    binds
                }
                Err(e) => {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            &format!("evaluating params: {e}"),
                            "invalid_spec",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
            };

            // On the resource surface a per-`{id}` `read_query` (when configured)
            // is the single-row read for a `resource_templates[]` binding; it
            // binds the same `params` (the gateway-extracted template vars reach
            // it as `arguments.<var>`) and is always a read (`op: query`). Every
            // other surface — and a resource binding without `read_query` — runs
            // the operator-fixed `query` with its declared `op`.
            let (effective_statement, effective_op) =
                match (profile.surface, profile.read_query.as_deref()) {
                    (surface::Surface::Resource, Some(rq)) => (rq, OracleOp::Query),
                    _ => (profile.query.as_str(), profile.op),
                };

            // rust-oracle is blocking and dlopen-bound; acquire a pooled
            // connection (lazily opened on first use), then run the statement on
            // a blocking thread, with the outer tokio timeout as a ceiling on top
            // of the ODPI-C call timeout. The pooled `Object` (Send) is moved into
            // the closure and dropped back to the pool when the closure returns.
            self.run_pooled(
                &profile,
                effective_statement,
                bound,
                effective_op,
                profile.size_limit,
            )
            .await
            .map(QueryOutcomeResult)
        };

        // The envelope `request.op` label reflects the binding's behaviour: the
        // catalog operations report `list_tables` / `list_columns`; the query
        // path reports the `op` (`query` / `execute`).
        let op_label = if profile.operation.is_catalog() {
            profile.operation.as_str()
        } else {
            profile.op.as_str()
        };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok(outcome) => {
                    // On the resource/prompt surfaces the gateway decoder
                    // requires a surface-shaped body; the tool surface keeps the
                    // historical envelope. A resource read with no resolvable URI
                    // falls back to the tool error envelope (carries
                    // `downstreamError` → gateway `is_error`) so the decoder sees
                    // a clean error rather than an invalid `{contents}`.
                    match profile.surface {
                        surface::Surface::Tool => (
                            build_result_envelope(
                                &tool_name,
                                backend_name,
                                &profile.dsn,
                                op_label,
                                outcome.0.rows.as_deref(),
                                outcome.0.rows_affected,
                                started.elapsed().as_millis(),
                                None,
                                None,
                            ),
                            "ok",
                            None,
                        ),
                        surface::Surface::Resource => {
                            let rows = outcome.0.rows.as_deref().unwrap_or(&[]);
                            match surface::resolve_resource_uri(
                                profile.surface_uri.as_deref(),
                                &arguments,
                            ) {
                                Some(uri) => {
                                    (surface::resource_contents_body(uri, rows), "ok", None)
                                }
                                None => {
                                    let message = "resource surface requires a `uri` (set a static `uri` on the binding or invoke via a resources/read request)".to_owned();
                                    let downstream = classify_error(&message);
                                    let env = build_result_envelope(
                                        &tool_name,
                                        backend_name,
                                        &profile.dsn,
                                        op_label,
                                        None,
                                        None,
                                        started.elapsed().as_millis(),
                                        Some(&downstream),
                                        Some(&message),
                                    );
                                    (env, "oracle_error", Some(message))
                                }
                            }
                        }
                        surface::Surface::Prompt => {
                            let rows = outcome.0.rows.as_deref().unwrap_or(&[]);
                            (surface::prompt_messages_body(rows), "ok", None)
                        }
                    }
                }
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "oracle_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.dsn,
                        op_label,
                        None,
                        None,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("oracle.transport".to_owned(), json!("plugin"));
        map
    }

    /// JSON Schema for the result envelope this binding emits. For the catalog
    /// operations the `response.rows` items are typed to the known `ALL_TABLES` /
    /// `ALL_TAB_COLUMNS` column set; the `query` op leaves rows untyped.
    fn output_schema(&self, backend_name: &str) -> Option<Value> {
        let op = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| g.get(backend_name).map(|p| p.operation))
            .unwrap_or(OracleOperation::Query);
        Some(match op {
            OracleOperation::Query => envelope::result_envelope_schema(),
            OracleOperation::ListTables => {
                envelope::catalog_envelope_schema(catalog::LIST_TABLES_COLUMNS)
            }
            OracleOperation::ListColumns => {
                envelope::catalog_envelope_schema(catalog::LIST_COLUMNS_COLUMNS)
            }
        })
    }

    /// JSON Schema for the tool arguments. The binding's positional `params`
    /// are CEL expressions over `arguments.*`; the referenced argument names
    /// are surfaced as untyped, optional properties. The object stays open
    /// (`additionalProperties: true`) so the schema never rejects valid args.
    fn input_schema(&self, backend_name: &str) -> Option<Value> {
        // `try_read` (sync, non-blocking): `input_schema` is called from the
        // gateway's registration path with no concurrent writer.
        let names: Vec<String> = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| {
                g.get(backend_name).map(|p| {
                    if p.operation.is_catalog() {
                        // Catalog ops take no CEL params; their callable args are
                        // the configured `owner_arg` / `table_arg` filter names.
                        p.catalog_filters.argument_names()
                    } else {
                        arguments_referenced_by_params(&p.compiled_params)
                    }
                })
            })
            .unwrap_or_default();
        Some(params_input_schema(&names))
    }

    /// Enumerate resources for `resources/list` via the operator-fixed
    /// `list_query` (run as an `op: query`). The `:1` (cursor) / `:2`
    /// (page_size) binds are the only non-operator values. Bindings without a
    /// `list_query` inherit the empty page.
    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(list_cfg) = profile.list_query.clone() else {
            return Ok(ResourcePage::empty());
        };

        let prior_offset = match (list_cfg.mode, cursor) {
            (ListQueryMode::Offset, Some(c)) => {
                c.parse::<u64>().map_err(|_| BackendError::InvalidSpec {
                    message: format!("offset-mode cursor '{c}' is not a non-negative integer"),
                })?
            }
            _ => 0,
        };
        let page_size_bind = OracleBind::Int(list_cfg.page_size as i64);
        let binds: Vec<OracleBind> = match list_cfg.mode {
            ListQueryMode::Keyset => vec![
                match cursor {
                    Some(c) => OracleBind::Str(c.to_owned()),
                    None => OracleBind::Null,
                },
                page_size_bind,
            ],
            ListQueryMode::Offset => {
                vec![page_size_bind, OracleBind::Int(prior_offset as i64)]
            }
        };

        let outcome = self
            .run_read_query(&profile, &list_cfg.sql, binds, list_cfg.page_size as usize)
            .await?;
        let rows = outcome.rows.unwrap_or_default();
        Ok(surface::rows_to_resource_page(
            &rows,
            &list_cfg,
            prior_offset,
        ))
    }

    /// Return completion candidates for a resource-template variable via the
    /// operator-fixed `variable_completions[<variable_name>]` query. The single
    /// `:1` is bound to the caller's typed `prefix` value. Unconfigured
    /// variables inherit the empty list.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(cc) = profile.variable_completions.get(variable_name).cloned() else {
            return Ok(vec![]);
        };
        let max = cc.max_results.unwrap_or(100) as usize;
        let outcome = self
            .run_read_query(
                &profile,
                &cc.sql,
                vec![OracleBind::Str(prefix.to_owned())],
                max,
            )
            .await?;
        let rows = outcome.rows.unwrap_or_default();
        let first_col = rows
            .first()
            .and_then(Value::as_object)
            .and_then(|m| m.keys().next().cloned());
        Ok(surface::rows_to_completion_values(
            &rows,
            first_col.as_deref(),
            max,
        ))
    }
}

impl OracleBackendPlugin {
    /// Acquire a pooled connection (lazily opened on first use) and run a
    /// statement on a blocking thread. The pooled `Object` is `Send`, so it is
    /// moved into the `spawn_blocking` closure; the runner borrows it (`&conn`)
    /// to prepare + bind + run, and dropping the `Object` at the end of the
    /// closure returns the connection to the pool. The outer tokio timeout caps
    /// pool-acquire + the whole blocking task on top of the ODPI-C call timeout.
    async fn run_pooled(
        &self,
        profile: &OracleProfile,
        sql: &str,
        binds: Vec<OracleBind>,
        op: OracleOp,
        size_limit: usize,
    ) -> Result<oracle::QueryOutcome, String> {
        let conn = match tokio::time::timeout(profile.timeout, profile.pool.get()).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(format!("Oracle pool acquire failed: {e}")),
            Err(_) => return Err("Oracle pool acquire timed out".to_owned()),
        };

        let sql = sql.to_owned();
        let call_timeout = profile.timeout;
        let blocking = tokio::task::spawn_blocking(move || {
            // `conn` (the pooled Object) is moved in and dropped here, returning
            // the connection to the pool when the statement completes.
            run_statement_blocking(&conn, &sql, binds, op, size_limit, call_timeout)
        });
        match tokio::time::timeout(profile.timeout, blocking).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(join_err)) => Err(format!("Oracle worker task failed: {join_err}")),
            Err(_) => Err("Oracle call timed out".to_owned()),
        }
    }

    /// Run an operator-fixed read statement (list / completion) against the
    /// pooled connection, mapping transport failures to
    /// [`BackendError::Transport`].
    async fn run_read_query(
        &self,
        profile: &OracleProfile,
        sql: &str,
        binds: Vec<OracleBind>,
        size_limit: usize,
    ) -> Result<oracle::QueryOutcome, BackendError> {
        self.run_pooled(profile, sql, binds, OracleOp::Query, size_limit)
            .await
            .map_err(|message| BackendError::Transport { message })
    }
}

/// Collect the distinct `arguments.<ident>` names referenced across a
/// binding's compiled CEL params, preserving first-seen order.
fn arguments_referenced_by_params(params: &[CompiledParam]) -> Vec<String> {
    let mut names = Vec::new();
    for p in params {
        for name in extract_argument_idents(&p.source) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Build an open object schema from the referenced argument names. With no
/// known names this is the permissive `{type:object, additionalProperties:true}`.
fn params_input_schema(names: &[String]) -> Value {
    let mut properties = serde_json::Map::new();
    for name in names {
        properties.insert(name.clone(), json!({}));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "additionalProperties": true,
    })
}

/// Extract identifiers appearing as `arguments.<ident>` in a CEL source
/// string. Pure string scan (no CEL deps) — a best-effort hint, never a
/// rejection surface.
fn extract_argument_idents(source: &str) -> Vec<String> {
    const MARKER: &str = "arguments.";
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(MARKER) {
        let start = search_from + rel + MARKER.len();
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            out.push(source[start..end].to_owned());
        }
        search_from = end.max(search_from + rel + MARKER.len());
    }
    out
}

/// Newtype so the `spawn_blocking` result type names cleanly above.
struct QueryOutcomeResult(oracle::QueryOutcome);

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "query": "SELECT 1 FROM dual WHERE id = :1",
            "params": ["arguments.id"],
        })
    }

    #[test]
    fn kind_is_oracle() {
        assert_eq!(OracleBackendPlugin::new().kind(), "oracle");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            OracleBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.oracle"
        );
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile("users", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("users").unwrap();
        assert_eq!(p.op, OracleOp::Query);
        assert_eq!(p.dsn, "//db.example.com:1521/ORCLPDB1");
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_builds_lazy_pool_without_connecting() {
        // The pool must be built at register time without opening any ODPI-C
        // connection (no Instant Client present in unit tests). A non-default
        // pool_max_size is accepted; the pool stays idle until the first call.
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["pool_max_size"] = json!(8);
        plugin
            .register_profile("users", &spec, no_op_host())
            .await
            .expect("register builds lazy pool with no connection");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("users").unwrap();
        // The lazy pool reports its configured capacity but holds no connection.
        assert_eq!(p.pool.status().max_size, 8);
        assert_eq!(p.pool.status().size, 0);
    }

    #[tokio::test]
    async fn register_rejects_zero_pool_max_size() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["pool_max_size"] = json!(0);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("zero pool_max_size");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[test]
    fn extract_argument_idents_finds_names() {
        let got = extract_argument_idents("arguments.user_id + size(arguments.tags)");
        assert_eq!(got, vec!["user_id".to_owned(), "tags".to_owned()]);
        assert!(extract_argument_idents("1 + 2").is_empty());
    }

    #[tokio::test]
    async fn register_defaults_to_tool_surface() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile("users", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("users").unwrap();
        assert_eq!(p.surface, surface::Surface::Tool);
        assert!(p.surface_uri.is_none());
    }

    #[tokio::test]
    async fn register_stores_resource_surface_and_uri() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["uri"] = json!("oracle://docs/all");
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("r").unwrap();
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.surface_uri.as_deref(), Some("oracle://docs/all"));
    }

    #[tokio::test]
    async fn register_rejects_uri_on_tool_surface() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["uri"] = json!("oracle://x");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("uri on tool surface");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// A resource_template binding may declare a per-`{id}` `read_query` and omit
    /// `query`; the profile stores it and stays read-only-guarded.
    #[tokio::test]
    async fn register_resource_template_read_query() {
        let plugin = OracleBackendPlugin::new();
        let spec = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "surface": "resource",
            "read_query": "SELECT * FROM orders WHERE id = :1",
            "params": ["arguments.id"],
        });
        plugin
            .register_profile("rt", &spec, no_op_host())
            .await
            .expect("read_query registers without a query");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("rt").unwrap();
        assert_eq!(
            p.read_query.as_deref(),
            Some("SELECT * FROM orders WHERE id = :1")
        );
        assert!(p.query.is_empty());
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_rejects_read_query_on_tool_surface() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["read_query"] = json!("SELECT * FROM t WHERE id = :1");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("read_query on tool surface");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("read_query"), "{message}");
                assert!(message.contains("surface: resource"), "{message}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_non_read_only_read_query() {
        let plugin = OracleBackendPlugin::new();
        let spec = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "surface": "resource",
            "read_query": "DELETE FROM orders WHERE id = :1",
            "params": ["arguments.id"],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-read-only read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bare_cred_read_query() {
        let plugin = OracleBackendPlugin::new();
        let spec = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "surface": "resource",
            "read_query": "SELECT * FROM t WHERE k = 'cred://aws/x#id'",
            "params": [],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred in read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// The gateway delivers the extracted template variable as `arguments.<var>`;
    /// the binding's `params` CEL bind it to the `read_query`'s `:1` placeholder.
    /// A value crafted to look like SQL is carried verbatim as a single scalar
    /// bind (an `OracleBind::Str`) — it is data for the driver to bind, never
    /// spliced into the statement text.
    #[test]
    fn template_var_binds_as_param_not_interpolated() {
        let compiled = params::compile_params(&["arguments.id".to_owned()]).unwrap();
        // What the gateway hands the backend for `oracle://orders/{id}` on a
        // read of `oracle://orders/1 OR 1=1; DROP TABLE orders`.
        let injection = "1 OR 1=1; DROP TABLE orders";
        let args = json!({
            "uri": format!("oracle://orders/{injection}"),
            "id": injection,
            "template_vars": { "id": injection },
        });
        let values = params::evaluate_params(&compiled, &args).unwrap();
        assert_eq!(values, vec![json!(injection)]);
        let bind = params::json_to_oracle_bind(values.into_iter().next().unwrap()).unwrap();
        // The whole injection string is one opaque scalar bind — the driver binds
        // it as a string parameter; it never reaches SQL as text.
        assert_eq!(bind, params::OracleBind::Str(injection.to_owned()));
    }

    /// The resource-read branch shapes a single fabricated row into the
    /// `resources/read` contract body keyed on the concrete (gateway-supplied)
    /// URI.
    #[test]
    fn resource_template_read_shapes_single_row_contents() {
        let uri = "oracle://orders/42";
        let row = json!({ "id": 42, "total": 19.99 });
        let body = surface::resource_contents_body(uri, std::slice::from_ref(&row));
        let contents = body["contents"].as_array().expect("contents");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!(uri));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let decoded: Vec<Value> =
            serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, vec![row]);
    }

    #[tokio::test]
    async fn output_schema_is_object() {
        let plugin = OracleBackendPlugin::new();
        let schema = BackendPlugin::output_schema(&plugin, "users").unwrap();
        assert_eq!(schema["type"], json!("object"));
    }

    #[tokio::test]
    async fn input_schema_lists_referenced_params() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile("users", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "users").unwrap();
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["additionalProperties"], json!(true));
        assert!(schema["properties"]["id"].is_object());
    }

    #[tokio::test]
    async fn register_rejects_cred_password() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["password"] = json!("cred://vault/oracle");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred password");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bad_cel_param() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["params"] = json!(["this is not cel ((("]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bad cel");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_empty_query() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!("   ");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = OracleBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    #[tokio::test]
    async fn list_resources_empty_when_unconfigured() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile("users", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let page = BackendPlugin::list_resources(&plugin, "users", None)
            .await
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn complete_template_variable_empty_when_unconfigured() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile("users", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "users",
            "v",
            "x",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn register_stores_list_query_and_completions() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["list_query"] = json!({
            "sql": "SELECT uri FROM docs WHERE id > :1 ORDER BY id FETCH FIRST :2 ROWS ONLY",
            "cursor_column": "id",
        });
        spec["variable_completions"] = json!({
            "name": { "sql": "SELECT name FROM docs WHERE name LIKE :1 || '%'" }
        });
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("r").unwrap();
        assert!(p.list_query.is_some());
        assert!(p.variable_completions.contains_key("name"));
    }

    #[tokio::test]
    async fn register_rejects_keyset_list_query_without_cursor() {
        let plugin = OracleBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["list_query"] = json!({ "sql": "SELECT uri FROM docs FETCH FIRST :2 ROWS ONLY" });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("missing cursor_column");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    // ---------------------------------------------------------------- catalog

    #[tokio::test]
    async fn register_list_tables_without_query_is_ok() {
        let plugin = OracleBackendPlugin::new();
        let spec = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "operation": "list_tables",
            "owner": "HR",
        });
        plugin
            .register_profile("t", &spec, no_op_host())
            .await
            .expect("list_tables needs no query");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("t").unwrap();
        assert_eq!(p.operation, OracleOperation::ListTables);
        assert_eq!(p.catalog_filters.owner.as_deref(), Some("HR"));
    }

    #[tokio::test]
    async fn register_list_columns_requires_table() {
        let plugin = OracleBackendPlugin::new();
        let spec = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "operation": "list_columns",
        });
        let err = plugin
            .register_profile("c", &spec, no_op_host())
            .await
            .expect_err("list_columns needs a table");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));

        // A `table_arg` satisfies the requirement (table chosen per call).
        let spec_ok = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "operation": "list_columns",
            "table_arg": "table",
        });
        plugin
            .register_profile("c2", &spec_ok, no_op_host())
            .await
            .expect("table_arg satisfies list_columns");
    }

    /// A catalog op must not require the `query` statement / read-only guard:
    /// it introspects `ALL_TABLES` / `ALL_TAB_COLUMNS`, never the operator SQL.
    #[tokio::test]
    async fn register_catalog_op_ignores_query() {
        let plugin = OracleBackendPlugin::new();
        let spec = json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "operation": "list_tables",
            "op": "execute",
            "query": "DELETE FROM ignored",
        });
        plugin
            .register_profile("t", &spec, no_op_host())
            .await
            .expect("catalog op ignores the query / op");
    }

    #[tokio::test]
    async fn output_schema_typed_for_catalog_ops() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile(
                "t",
                &json!({
                    "dsn": "//db.example.com:1521/ORCLPDB1",
                    "username": "svc",
                    "password": "${env.ORACLE_PW}",
                    "operation": "list_tables",
                }),
                no_op_host(),
            )
            .await
            .expect("register");
        let schema = BackendPlugin::output_schema(&plugin, "t").unwrap();
        let items = &schema["properties"]["response"]["properties"]["rows"]["items"];
        assert_eq!(items["type"], json!("object"));
        assert!(items["properties"]["OWNER"].is_object());
        assert!(items["properties"]["TABLE_NAME"].is_object());
    }

    #[tokio::test]
    async fn input_schema_lists_catalog_argument_names() {
        let plugin = OracleBackendPlugin::new();
        plugin
            .register_profile(
                "c",
                &json!({
                    "dsn": "//db.example.com:1521/ORCLPDB1",
                    "username": "svc",
                    "password": "${env.ORACLE_PW}",
                    "operation": "list_columns",
                    "table_arg": "table",
                    "owner_arg": "owner",
                }),
                no_op_host(),
            )
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "c").unwrap();
        assert!(schema["properties"]["table"].is_object());
        assert!(schema["properties"]["owner"].is_object());
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
