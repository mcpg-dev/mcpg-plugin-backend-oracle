//! Operator-facing spec for the Oracle backend plugin.
//!
//! One binding = one parameterised statement = one MCP tool (or resource).
//! The connection (dsn/username/password) and the statement (query/params/op)
//! all live on the per-binding spec, mirroring the http/soap/ldap/mssql
//! one-profile-per-binding shape.

use serde::Deserialize;

/// What the statement does — selects rows, or mutates and reports a count.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OracleOp {
    /// `SELECT`-style: return the matched rows.
    #[default]
    Query,
    /// `INSERT` / `UPDATE` / `DELETE` / DDL / PL-SQL: return rows-affected.
    Execute,
}

impl OracleOp {
    pub fn as_str(self) -> &'static str {
        match self {
            OracleOp::Query => "query",
            OracleOp::Execute => "execute",
        }
    }
}

/// What the binding does. `query` (default) runs the operator-fixed `query`
/// statement (driven by `op` / `params`); `list_tables` / `list_columns`
/// introspect Oracle's data dictionary (`ALL_TABLES` / `ALL_TAB_COLUMNS`) for
/// schema discovery. The catalog operations are inherently read-only metadata
/// reads — they ignore `op` / `params` (no read-only guard / CEL binds apply).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleOperation {
    /// Run the operator-fixed `query` statement with `:1, :2, …` binds (default).
    #[default]
    Query,
    /// Discover tables/views via `ALL_TABLES` (visible to the connected user).
    ListTables,
    /// Discover a table's columns via `ALL_TAB_COLUMNS`.
    ListColumns,
}

impl OracleOperation {
    /// Lowercase wire token (matches the `serde` rename).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OracleOperation::Query => "query",
            OracleOperation::ListTables => "list_tables",
            OracleOperation::ListColumns => "list_columns",
        }
    }

    /// Whether this is a data-dictionary introspection operation (inherently
    /// read-only, driven by `ALL_TABLES` / `ALL_TAB_COLUMNS`, not the `query`).
    #[must_use]
    pub fn is_catalog(self) -> bool {
        matches!(
            self,
            OracleOperation::ListTables | OracleOperation::ListColumns
        )
    }
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `OracleBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct OracleBackendSpec {
    /// Oracle data source name — an Easy Connect string
    /// (`//host:1521/SERVICE`) or a TNS alias. Operator-configured (not
    /// caller-templated), so there is no SSRF/arg-injection vector on the dsn.
    /// The listener port lives inside the dsn (there is no separate `port`).
    pub dsn: String,

    /// Database username.
    pub username: String,

    /// Login password. A literal, or a `${env.X}` / `vault://...` /
    /// `${cred://...}` reference the gateway secret-resolver expands at config
    /// load — never plaintext in committed config. (A bare per-caller
    /// `cred://` is rejected: the connection is one service identity — see
    /// README.)
    pub password: String,

    /// What the binding does. `query` (default) runs the operator-fixed
    /// `query` statement; `list_tables` / `list_columns` introspect Oracle's
    /// data dictionary (`ALL_TABLES` / `ALL_TAB_COLUMNS`). The catalog
    /// operations ignore `query` / `op` / `params` (they are inherently
    /// read-only metadata reads).
    #[serde(default)]
    pub operation: OracleOperation,

    /// The statement for `operation: query`. Uses `:1, :2, …` positional bind
    /// placeholders bound from `params`. The statement text is operator-fixed —
    /// it is NOT templated from caller arguments. Required for
    /// `operation: query`; ignored (and may be omitted) for the catalog
    /// operations.
    #[serde(default)]
    pub query: String,

    /// Statement kind (default `query`). `query` op only.
    #[serde(default)]
    pub op: OracleOp,

    /// Static owner/schema filter for `operation: list_tables` / `list_columns`.
    /// Bound as the `:owner` data-dictionary parameter (NEVER interpolated into
    /// SQL). When absent (and no `owner_arg` supplies one) the catalog query
    /// defaults to the connected user's current schema (`USER`). Oracle owners
    /// are case-sensitive and stored upper-cased.
    #[serde(default)]
    pub owner: Option<String>,

    /// Static table-name filter. For `operation: list_columns` this is the
    /// table whose columns are listed (required there via this field or
    /// `table_arg`). For `list_tables` it narrows to one table. Bound as the
    /// `:tbl` data-dictionary parameter — never interpolated into SQL.
    #[serde(default)]
    pub table: Option<String>,

    /// Tool-argument name supplying the owner/schema filter at call time. When
    /// set and present as a string in the call arguments, the caller value
    /// overrides the static `owner`. Bound as `:owner` — never interpolated.
    #[serde(default)]
    pub owner_arg: Option<String>,

    /// Tool-argument name supplying the table filter at call time. When set and
    /// present as a string in the call arguments, the caller value overrides the
    /// static `table`. Bound as `:tbl` — never interpolated.
    #[serde(default)]
    pub table_arg: Option<String>,

    /// Ordered CEL expressions; `params[i]` → `:{i+1}`. Each is evaluated
    /// against the call arguments (`arguments.*`) and bound as a SQL
    /// parameter — injection-safe.
    #[serde(default)]
    pub params: Vec<String>,

    /// Client-side cap on returned rows (default 100). `query` op only.
    #[serde(default = "default_size_limit")]
    pub size_limit: usize,

    /// Per-call timeout (ms) for connect + statement + read (default 10 s).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum pooled connections for this binding (default 4). Connections are
    /// opened lazily on first use and reused across calls; this caps how many
    /// concurrent ODPI-C sessions the binding may hold.
    #[serde(default = "default_pool_max_size")]
    pub pool_max_size: usize,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// tool envelope; `resource` reshapes successful rows into the
    /// `resources/read` `{contents:[…]}` body; `prompt` reshapes them into the
    /// `prompts/get` `{messages:[…]}` body. Set to match the capability list the
    /// binding is placed under (`resources[]` / `prompts[]`).
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// Optional static resource URI for `surface: resource`. When set it is used
    /// verbatim as the emitted content `uri`; when omitted the binding uses the
    /// requested URI the gateway passes in the call arguments (`uri`). Ignored
    /// for `tool` / `prompt` surfaces.
    #[serde(default)]
    pub uri: Option<String>,

    /// Optional listing statement for `resources/list`. On a
    /// `surface: resource` binding this runs at list time to enumerate concrete
    /// resource URIs. Operator-fixed; the only caller-derived inputs are the
    /// paginated `:1` (cursor) / `:2` (page_size) binds. Empty → the binding
    /// returns no dynamic listing (the trait default).
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,

    /// Optional per-`{id}` single-row read statement for a `resource_templates[]`
    /// binding (`surface: resource` with a `uri_template` like
    /// `oracle://orders/{id}`). On a `resources/read` of a concrete URI the
    /// gateway extracts the template variables and supplies them in the call
    /// arguments (each `{var}` as `arguments.<var>`); this statement's
    /// `:1, :2, …` placeholders are bound from the binding's `params` CEL
    /// expressions (`arguments.<var>`), so the extracted value binds SERVER-SIDE
    /// as a query parameter — never interpolated into SQL (injection-safe). When
    /// omitted the resource-read branch falls back to `query`. Operator-fixed;
    /// required to be read-only (SELECT/WITH).
    #[serde(default)]
    pub read_query: Option<String>,

    /// Optional per-template-variable completion config for
    /// `completion/complete`. Keyed by the URI template variable name; each
    /// entry is an operator-fixed query whose single `:1` is bound to the
    /// caller-typed prefix (never interpolated — injection-safe). Empty → no
    /// completion candidates (the trait default).
    #[serde(default)]
    pub variable_completions: std::collections::BTreeMap<String, CompletionConfig>,
}

/// Pagination strategy for [`ListQueryConfig`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListQueryMode {
    /// `WHERE cursor_column > :1 ORDER BY cursor_column FETCH FIRST :2 ROWS …`.
    /// `:1` is the keyset cursor (NULL first page); `:2` is page_size.
    #[default]
    Keyset,
    /// `OFFSET :2 ROWS FETCH NEXT :1 ROWS ONLY` — `:1` is page_size, `:2` the
    /// offset. O(offset) on the engine; use only for small listings.
    Offset,
}

/// Operator-fixed listing statement + pagination shape for `resources/list`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListQueryConfig {
    /// SELECT returning one row per resource. Required column: `uri`. Optional:
    /// `name`, `description`, `mime_type`. Operator-fixed; the `:1`/`:2`
    /// pagination binds are the only non-operator values.
    pub sql: String,
    /// Pagination mode — `keyset` (default) or `offset`.
    #[serde(default)]
    pub mode: ListQueryMode,
    /// Column the keyset cursor tracks. Required for `mode: keyset`; ignored for
    /// `mode: offset`.
    #[serde(default)]
    pub cursor_column: Option<String>,
    /// Rows per page (1..=1000). Defaults to 100.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

/// Operator-fixed completion query for one template variable.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompletionConfig {
    /// SQL returning candidate values in its first column. MUST reference a
    /// single `:1` placeholder — bound to the caller-typed prefix at call time
    /// (e.g. `SELECT name FROM repos WHERE name LIKE :1 || '%'`).
    pub sql: String,
    /// Optional cap on returned candidates; defaults to 100.
    #[serde(default)]
    pub max_results: Option<u32>,
}

fn default_size_limit() -> usize {
    100
}
fn default_timeout_ms() -> u64 {
    10_000
}
fn default_pool_max_size() -> usize {
    4
}
fn default_list_page_size() -> u64 {
    100
}

/// Fail-closed validation for an operator-fixed [`ListQueryConfig`].
pub fn validate_list_query(cfg: &ListQueryConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err("list_query.sql must not be empty".into());
    }
    if cfg.page_size == 0 || cfg.page_size > 1_000 {
        return Err(format!(
            "list_query.page_size ({}) must be in 1..=1000",
            cfg.page_size
        ));
    }
    if cfg.mode == ListQueryMode::Keyset {
        let col = cfg.cursor_column.as_deref().unwrap_or("").trim();
        if col.is_empty() {
            return Err("list_query.cursor_column is required for mode: keyset".into());
        }
        if !is_safe_sql_identifier(col) {
            return Err(format!(
                "list_query.cursor_column '{col}' is not a safe SQL identifier"
            ));
        }
    }
    Ok(())
}

/// Validate an operator-fixed [`CompletionConfig`]: non-empty SQL referencing
/// exactly one `:1` placeholder (the bound prefix).
pub fn validate_completion(name: &str, cfg: &CompletionConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err(format!("variable_completions.{name}.sql must not be empty"));
    }
    if !cfg.sql.contains(":1") {
        return Err(format!(
            "variable_completions.{name}.sql must reference the `:1` placeholder (bound to the typed prefix)"
        ));
    }
    Ok(())
}

/// A safe SQL identifier — `[A-Za-z_][A-Za-z0-9_]*`. Fences the operator-
/// declared keyset `cursor_column`, which is interpolated into the next-cursor
/// projection.
fn is_safe_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_defaults_to_query() {
        assert_eq!(OracleOp::default(), OracleOp::Query);
    }

    #[test]
    fn spec_applies_defaults() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//db.example.com:1521/ORCLPDB1",
            "username": "svc",
            "password": "${env.ORACLE_PW}",
            "query": "SELECT id, name FROM users WHERE id = :1",
            "params": ["arguments.id"],
        }))
        .unwrap();
        assert_eq!(spec.op, OracleOp::Query);
        assert_eq!(spec.size_limit, 100);
        assert_eq!(spec.timeout_ms, 10_000);
        assert_eq!(spec.pool_max_size, 4);
        assert_eq!(spec.params, vec!["arguments.id".to_owned()]);
    }

    #[test]
    fn parses_list_query_and_completions() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "query": "SELECT 1 FROM dual",
            "surface": "resource",
            "list_query": {
                "sql": "SELECT uri FROM docs WHERE id > :1 ORDER BY id FETCH FIRST :2 ROWS ONLY",
                "cursor_column": "id",
                "page_size": 50,
            },
            "variable_completions": {
                "name": { "sql": "SELECT name FROM docs WHERE name LIKE :1 || '%'" },
            },
        }))
        .unwrap();
        let lq = spec.list_query.expect("list_query");
        assert_eq!(lq.page_size, 50);
        assert_eq!(lq.cursor_column.as_deref(), Some("id"));
        assert!(spec.variable_completions.contains_key("name"));
    }

    #[test]
    fn validate_list_query_enforces_cursor_and_bounds() {
        let mut cfg = ListQueryConfig {
            sql: "SELECT uri FROM t".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(validate_list_query(&cfg).is_err());
        cfg.cursor_column = Some("id".into());
        assert!(validate_list_query(&cfg).is_ok());
        cfg.cursor_column = Some("id;DROP".into());
        assert!(validate_list_query(&cfg).is_err());
        cfg.cursor_column = Some("id".into());
        cfg.page_size = 5000;
        assert!(validate_list_query(&cfg).is_err());
    }

    #[test]
    fn validate_completion_requires_placeholder() {
        let mut cc = CompletionConfig {
            sql: "SELECT name FROM t WHERE name LIKE :1 || '%'".into(),
            max_results: None,
        };
        assert!(validate_completion("name", &cc).is_ok());
        cc.sql = "SELECT name FROM t".into();
        assert!(validate_completion("name", &cc).is_err());
        cc.sql = "   ".into();
        assert!(validate_completion("name", &cc).is_err());
    }

    #[test]
    fn operation_defaults_to_query() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "query": "SELECT 1 FROM dual",
        }))
        .unwrap();
        assert_eq!(spec.operation, OracleOperation::Query);
        assert!(!spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "query");
    }

    #[test]
    fn parses_list_tables_operation_with_filters() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "operation": "list_tables",
            "owner": "HR",
            "owner_arg": "owner",
        }))
        .unwrap();
        assert_eq!(spec.operation, OracleOperation::ListTables);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "list_tables");
        assert_eq!(spec.owner.as_deref(), Some("HR"));
        assert_eq!(spec.owner_arg.as_deref(), Some("owner"));
        // `query` may be omitted for catalog operations.
        assert!(spec.query.is_empty());
    }

    #[test]
    fn parses_list_columns_operation() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "operation": "list_columns",
            "table": "EMPLOYEES",
            "table_arg": "table",
        }))
        .unwrap();
        assert_eq!(spec.operation, OracleOperation::ListColumns);
        assert_eq!(spec.table.as_deref(), Some("EMPLOYEES"));
        assert_eq!(spec.table_arg.as_deref(), Some("table"));
    }

    #[test]
    fn parses_resource_template_read_query() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "surface": "resource",
            "read_query": "SELECT * FROM orders WHERE id = :1",
            "params": ["arguments.id"],
        }))
        .unwrap();
        assert_eq!(
            spec.read_query.as_deref(),
            Some("SELECT * FROM orders WHERE id = :1")
        );
        // `query` may be omitted when `read_query` carries the read.
        assert!(spec.query.is_empty());
        assert_eq!(spec.params, vec!["arguments.id".to_owned()]);
    }

    #[test]
    fn read_query_defaults_to_none() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "query": "SELECT 1 FROM dual",
        }))
        .unwrap();
        assert!(spec.read_query.is_none());
    }

    #[test]
    fn parses_execute_op() {
        let spec: OracleBackendSpec = serde_json::from_value(serde_json::json!({
            "dsn": "//h:1521/S", "username": "u", "password": "p",
            "query": "UPDATE t SET v = :1 WHERE id = :2",
            "op": "execute",
            "params": ["arguments.v", "arguments.id"],
        }))
        .unwrap();
        assert_eq!(spec.op, OracleOp::Execute);
    }
}
