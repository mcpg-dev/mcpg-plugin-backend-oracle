//! Data-dictionary introspection for `operation: list_tables` / `list_columns`.
//!
//! Schema discovery runs ordinary `SELECT`s against Oracle's `ALL_TABLES` /
//! `ALL_TAB_COLUMNS` dictionary views — the `ALL_*` family shows objects the
//! connected user may access (no elevated `DBA_*` / `SELECT ANY DICTIONARY`
//! privilege needed). Every operator/caller filter is bound as a `:owner` /
//! `:tbl` SQL parameter (NEVER interpolated into the statement text), so a
//! caller-supplied filter can only narrow the metadata — it can never alter the
//! query (injection-safe, same contract as the `query` op's `params`).

use serde_json::Value;

use crate::params::OracleBind;
use crate::types::OracleOperation;

/// One resolved set of catalog filters for a single call: the owner/schema and
/// (for `list_columns`) the table whose columns to list. A `None` field means
/// "no filter" — `owner: None` falls back to the connected user's `USER` schema
/// in the generated SQL; `table: None` lists across all visible tables.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CatalogFilters {
    pub owner: Option<String>,
    pub table: Option<String>,
}

/// Per-binding catalog filter config: an operator-pinned static value plus an
/// optional tool-argument name for each of `owner` / `table`. The per-call
/// argument (when configured AND present as a JSON string) overrides the static
/// value; every resolved value is bound as a SQL parameter by [`build_query`].
#[derive(Debug, Default, Clone)]
pub struct CatalogFilterConfig {
    pub owner: Option<String>,
    pub table: Option<String>,
    pub owner_arg: Option<String>,
    pub table_arg: Option<String>,
}

impl CatalogFilterConfig {
    /// Resolve the filters for one call. For each, the per-call argument (when
    /// configured and present as a non-empty JSON string) wins over the static
    /// value; otherwise the static value (or `None` = no filter) is used.
    #[must_use]
    pub fn resolve(&self, arguments: &Value) -> CatalogFilters {
        CatalogFilters {
            owner: resolve_one(self.owner.as_deref(), self.owner_arg.as_deref(), arguments),
            table: resolve_one(self.table.as_deref(), self.table_arg.as_deref(), arguments),
        }
    }

    /// The distinct tool-argument names this config reads from call arguments,
    /// in filter order — surfaced as the catalog op's `input_schema` properties.
    #[must_use]
    pub fn argument_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for arg in [&self.owner_arg, &self.table_arg].into_iter().flatten() {
            if !names.contains(arg) {
                names.push(arg.clone());
            }
        }
        names
    }
}

/// Resolve a single filter: a caller-supplied non-empty string argument (when
/// `arg_name` is configured and present) overrides the operator-pinned
/// `static_value`; absent both, `None` = no filter.
fn resolve_one(
    static_value: Option<&str>,
    arg_name: Option<&str>,
    arguments: &Value,
) -> Option<String> {
    if let Some(name) = arg_name
        && let Some(v) = arguments.get(name).and_then(Value::as_str)
        && !v.is_empty()
    {
        return Some(v.to_owned());
    }
    static_value
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Build the data-dictionary `SELECT` and its ordinal bind list for a catalog
/// operation. Filters are emitted as `:owner` / `:tbl` named placeholders and
/// bound POSITIONALLY (rust-oracle binds the array by appearance order), so the
/// returned `Vec<OracleBind>` lines up with the placeholders in the SQL. The
/// statement text is fully operator/plugin-fixed; caller input only ever flows
/// in as a bound value.
///
/// `list_tables` → `ALL_TABLES` (owner, table_name, tablespace_name).
/// `list_columns` → `ALL_TAB_COLUMNS` (owner, table_name, column_name,
/// data_type, data_length, nullable, column_id).
#[must_use]
pub fn build_query(
    operation: OracleOperation,
    filters: &CatalogFilters,
) -> (String, Vec<OracleBind>) {
    let mut binds = Vec::new();
    // `:owner` defaults to the connected user's schema (`USER`) when no owner
    // filter is supplied — the common "my schema" case. Otherwise it is bound.
    let owner_pred = match &filters.owner {
        Some(owner) => {
            binds.push(OracleBind::Str(owner.clone()));
            "owner = :owner"
        }
        None => "owner = USER",
    };

    let sql = match operation {
        OracleOperation::ListTables => {
            let mut sql = format!(
                "SELECT owner, table_name, tablespace_name \
                 FROM all_tables WHERE {owner_pred}"
            );
            if let Some(table) = &filters.table {
                binds.push(OracleBind::Str(table.clone()));
                sql.push_str(" AND table_name = :tbl");
            }
            sql.push_str(" ORDER BY owner, table_name");
            sql
        }
        OracleOperation::ListColumns => {
            let mut sql = format!(
                "SELECT owner, table_name, column_name, data_type, data_length, nullable, column_id \
                 FROM all_tab_columns WHERE {owner_pred}"
            );
            if let Some(table) = &filters.table {
                binds.push(OracleBind::Str(table.clone()));
                sql.push_str(" AND table_name = :tbl");
            }
            sql.push_str(" ORDER BY owner, table_name, column_id");
            sql
        }
        // The query op never reaches this path (dispatched by `execute`).
        OracleOperation::Query => "SELECT 1 FROM dual".to_owned(),
    };
    (sql, binds)
}

/// Column names a `list_tables` (`ALL_TABLES`) result yields — Oracle reports
/// unquoted column names upper-cased.
pub const LIST_TABLES_COLUMNS: &[&str] = &["OWNER", "TABLE_NAME", "TABLESPACE_NAME"];

/// Column names a `list_columns` (`ALL_TAB_COLUMNS`) result yields.
pub const LIST_COLUMNS_COLUMNS: &[&str] = &[
    "OWNER",
    "TABLE_NAME",
    "COLUMN_NAME",
    "DATA_TYPE",
    "DATA_LENGTH",
    "NULLABLE",
    "COLUMN_ID",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_one_prefers_present_string_argument() {
        // Per-call argument overrides the static value when present as a string.
        assert_eq!(
            resolve_one(Some("STATIC"), Some("owner"), &json!({ "owner": "LIVE" })),
            Some("LIVE".to_owned())
        );
        // Falls back to the static value when the argument is absent.
        assert_eq!(
            resolve_one(Some("STATIC"), Some("owner"), &json!({})),
            Some("STATIC".to_owned())
        );
        // Non-string / empty argument is ignored (falls back to static).
        assert_eq!(
            resolve_one(Some("STATIC"), Some("owner"), &json!({ "owner": 7 })),
            Some("STATIC".to_owned())
        );
        assert_eq!(
            resolve_one(Some("STATIC"), Some("owner"), &json!({ "owner": "" })),
            Some("STATIC".to_owned())
        );
        // No static, no arg → None = no filter.
        assert_eq!(resolve_one(None, None, &json!({})), None);
    }

    #[test]
    fn filter_config_resolves_both() {
        let cfg = CatalogFilterConfig {
            owner: Some("HR".into()),
            table: Some("EMPLOYEES".into()),
            owner_arg: Some("owner".into()),
            table_arg: Some("table".into()),
        };
        let f = cfg.resolve(&json!({ "owner": "SALES" }));
        assert_eq!(f.owner.as_deref(), Some("SALES")); // arg override
        assert_eq!(f.table.as_deref(), Some("EMPLOYEES")); // static (no arg)
    }

    #[test]
    fn filter_config_argument_names_are_distinct_in_order() {
        let cfg = CatalogFilterConfig {
            owner_arg: Some("owner".into()),
            // duplicate name across slots collapses to one entry.
            table_arg: Some("owner".into()),
            ..Default::default()
        };
        assert_eq!(cfg.argument_names(), vec!["owner".to_owned()]);
    }

    #[test]
    fn list_tables_defaults_owner_to_current_user_no_binds() {
        let (sql, binds) = build_query(OracleOperation::ListTables, &CatalogFilters::default());
        assert!(sql.contains("FROM all_tables"));
        assert!(sql.contains("owner = USER"), "{sql}");
        assert!(
            !sql.contains(":owner"),
            "no owner bind when defaulted: {sql}"
        );
        // No filter → no caller-derived data interpolated and no binds.
        assert!(binds.is_empty());
        assert!(sql.contains("ORDER BY owner, table_name"));
    }

    #[test]
    fn list_tables_binds_owner_and_table_as_params() {
        let filters = CatalogFilters {
            owner: Some("HR".into()),
            table: Some("EMPLOYEES".into()),
        };
        let (sql, binds) = build_query(OracleOperation::ListTables, &filters);
        // Filters appear ONLY as bind placeholders, never interpolated values.
        assert!(sql.contains("owner = :owner"), "{sql}");
        assert!(sql.contains("table_name = :tbl"), "{sql}");
        assert!(!sql.contains("HR"), "owner must not be interpolated: {sql}");
        assert!(
            !sql.contains("EMPLOYEES"),
            "table must not be interpolated: {sql}"
        );
        // Binds line up positionally with placeholder appearance order.
        assert_eq!(
            binds,
            vec![
                OracleBind::Str("HR".into()),
                OracleBind::Str("EMPLOYEES".into()),
            ]
        );
    }

    #[test]
    fn list_columns_selects_expected_dictionary_columns() {
        let filters = CatalogFilters {
            owner: Some("HR".into()),
            table: Some("EMPLOYEES".into()),
        };
        let (sql, binds) = build_query(OracleOperation::ListColumns, &filters);
        assert!(sql.contains("FROM all_tab_columns"), "{sql}");
        for col in [
            "column_name",
            "data_type",
            "data_length",
            "nullable",
            "column_id",
        ] {
            assert!(sql.contains(col), "missing {col}: {sql}");
        }
        assert!(sql.contains("owner = :owner") && sql.contains("table_name = :tbl"));
        assert_eq!(
            binds,
            vec![
                OracleBind::Str("HR".into()),
                OracleBind::Str("EMPLOYEES".into()),
            ]
        );
    }

    #[test]
    fn injection_attempt_in_filter_stays_a_bound_value() {
        // A hostile owner value flows in ONLY as a bind — the SQL text is fixed.
        let filters = CatalogFilters {
            owner: Some("HR' OR '1'='1".into()),
            table: None,
        };
        let (sql, binds) = build_query(OracleOperation::ListTables, &filters);
        assert!(
            !sql.contains("OR '1'='1"),
            "payload must not reach SQL: {sql}"
        );
        assert_eq!(binds, vec![OracleBind::Str("HR' OR '1'='1".into())]);
    }

    #[test]
    fn column_sets_match_select_lists() {
        // Sanity: the typed output_schema column sets reflect the SELECT lists.
        assert_eq!(LIST_TABLES_COLUMNS.len(), 3);
        assert_eq!(LIST_COLUMNS_COLUMNS.len(), 7);
        assert!(LIST_COLUMNS_COLUMNS.contains(&"DATA_TYPE"));
    }
}
