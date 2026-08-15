//! Oracle structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is
//! the gateway's `is_error` signal (same contract as the http/soap/ldap/mssql
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn oracle_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_oracle.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_database_connectivity_and_retry" } else { "inspect_sql_error" },
    })
}

/// Classify a `run_statement` error string. Connection-level failures
/// (connect / login / pool / timeout / dropped connection — the `ORA-0305x`
/// "connection closed / not connected" family) are retryable transport errors;
/// SQL rejections (syntax, constraint, permission) are caller/config problems
/// and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    let retryable = lower.contains("connect")
        || lower.contains("login failed")
        || lower.contains("pool")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        || lower.contains("eof")
        // ORA-03113 end-of-file, ORA-03114 not connected, ORA-03135 lost
        // contact — dropped-connection markers worth a retry.
        || lower.contains("ora-0305")
        || lower.contains("ora-03113")
        || lower.contains("ora-03114")
        || lower.contains("ora-03135");
    let kind = if retryable {
        "transport_error"
    } else {
        "oracle_error"
    };
    oracle_downstream_error(kind, message, retryable)
}

/// JSON Schema (draft 2020-12) for the fixed envelope wrapper
/// [`build_result_envelope`] produces. Describes the stable top-level
/// shape (`toolName`/`profile`/`request`/`response`/`downstreamError`/
/// `error`); per-query `response.rows` items are intentionally left
/// untyped (`{}`) so any row shape validates.
pub fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "toolName": { "type": "string" },
            "profile": { "type": "string" },
            "request": {
                "type": "object",
                "properties": {
                    "dsn": { "type": "string" },
                    "op": { "type": "string" }
                },
                "additionalProperties": true
            },
            "response": {
                "type": ["object", "null"],
                "properties": {
                    "rows": { "type": ["array", "null"], "items": {} },
                    "count": { "type": ["integer", "null"] },
                    "rowsAffected": { "type": ["integer", "null"] },
                    "durationMs": { "type": "integer" }
                },
                "additionalProperties": true
            },
            "downstreamError": { "type": ["object", "null"] },
            "downstreamErrors": { "type": "array", "items": {} },
            "error": { "type": ["string", "null"] }
        },
        "additionalProperties": true
    })
}

/// Envelope schema specialized for a catalog-introspection operation: the same
/// wrapper as [`result_envelope_schema`] but with `response.rows` items typed to
/// the known `ALL_TABLES` / `ALL_TAB_COLUMNS` column set. The object stays open
/// (`additionalProperties: true`) so a row never fails validation.
pub fn catalog_envelope_schema(columns: &[&str]) -> Value {
    let mut schema = result_envelope_schema();
    let mut props = serde_json::Map::new();
    for col in columns {
        // Dictionary cells are projected by Oracle type → numbers stay numbers,
        // text stays text; type them loosely (string | number | null).
        props.insert(
            (*col).to_owned(),
            json!({ "type": ["string", "number", "null"] }),
        );
    }
    schema["properties"]["response"]["properties"]["rows"]["items"] = json!({
        "type": "object",
        "properties": Value::Object(props),
        "additionalProperties": true,
    });
    schema
}

/// Build the Oracle structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    dsn: &str,
    op: &str,
    rows: Option<&[Value]>,
    rows_affected: Option<u64>,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "rows": rows,
            "count": rows.map(<[Value]>::len),
            "rowsAffected": rows_affected,
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "dsn": dsn,
            "op": op,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failure_is_retryable_transport_error() {
        let e = classify_error("Oracle connect/login failed: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn dropped_connection_ora_marker_is_retryable() {
        let e = classify_error("Oracle query failed: ORA-03114: not connected to ORACLE");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn sql_rejection_is_not_retryable() {
        let e = classify_error("Oracle query failed: ORA-00904: \"BOGUS\": invalid identifier");
        assert_eq!(e["kind"], json!("oracle_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn query_envelope_has_rows_and_count() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "//db:1521/ORCLPDB1",
            "query",
            Some(&rows),
            None,
            7,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["rows"][0]["id"], json!(1));
        assert_eq!(env["request"]["dsn"], json!("//db:1521/ORCLPDB1"));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn execute_envelope_has_rows_affected() {
        let env = build_result_envelope(
            "u.upd",
            "u.upd",
            "//db:1521/ORCLPDB1",
            "execute",
            None,
            Some(3),
            4,
            None,
            None,
        );
        assert_eq!(env["response"]["rowsAffected"], json!(3));
    }

    #[test]
    fn error_envelope_nulls_response() {
        let d = classify_error("Oracle execute failed: ORA-00001: unique constraint violated");
        let env = build_result_envelope(
            "u.upd",
            "u.upd",
            "//db:1521/ORCLPDB1",
            "execute",
            None,
            None,
            2,
            Some(&d),
            Some("unique constraint violated"),
        );
        assert!(env["response"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("oracle_error"));
    }

    #[test]
    fn catalog_schema_types_the_known_columns() {
        let schema = catalog_envelope_schema(&["OWNER", "TABLE_NAME", "COLUMN_ID"]);
        let items = &schema["properties"]["response"]["properties"]["rows"]["items"];
        assert_eq!(items["type"], json!("object"));
        assert!(items["properties"]["OWNER"].is_object());
        assert!(items["properties"]["TABLE_NAME"].is_object());
        assert!(items["properties"]["COLUMN_ID"].is_object());
        // Open object — drivers/extra projections never fail validation.
        assert_eq!(items["additionalProperties"], json!(true));
    }

    #[test]
    fn output_schema_matches_envelope_shape() {
        let schema = result_envelope_schema();
        assert_eq!(schema["type"], json!("object"));

        // Every property key the builder emits is declared in the schema.
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "//db:1521/ORCLPDB1",
            "query",
            Some(&rows),
            None,
            7,
            None,
            None,
        );
        let props = schema["properties"].as_object().expect("properties object");
        for key in env.as_object().expect("envelope object").keys() {
            assert!(props.contains_key(key), "schema missing key `{key}`");
        }
        // Loose row typing — any row shape validates.
        assert_eq!(
            schema["properties"]["response"]["properties"]["rows"]["items"],
            json!({})
        );
    }
}
