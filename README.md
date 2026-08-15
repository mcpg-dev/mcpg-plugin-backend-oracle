# `mcpg-plugin-backend-oracle`

Oracle Database backend binding plugin for mcpg (`kind: oracle`). Runs a
parameterised SQL / PL-SQL statement as MCP **tools** and **resources** — the
`:1, :2, …` positional placeholders are bound from CEL expressions evaluated
against the tool arguments (bound as SQL **parameters**, never
string-interpolated, so injection-safe), over a rust-oracle / ODPI-C
connection.

The Oracle complement to the `sql` backend (Postgres / MySQL / SQLite) and the
`mssql` backend (SQL Server) — neither of those drivers can speak to Oracle.

## How it works

One binding = one statement = one MCP tool (or resource). Per call:

1. Each `params[i]` CEL expression is evaluated against the call's
   `arguments` object, producing a value that is **bound** to `:{i+1}`.
   Values cross the wire as Oracle bind variables — the statement text is
   operator-fixed and never templated from caller input, so a caller cannot
   alter the query (injection defense).
2. A connection drawn from the binding's lazy connection pool runs the
   statement: `op: query` returns the rows (each projected to JSON by column
   type); `op: execute` runs the mutation / PL-SQL, commits, and returns the
   rows-affected count. The connection is returned to the pool and reused by
   later calls (see **Connection pooling** below).
3. SQL rejections and transport failures become a structured
   `downstreamError` (the gateway's `isError` signal); connect / login /
   timeout / dropped-connection failures are marked retryable.

## Driver / runtime

The driver is [`rust-oracle`](https://crates.io/crates/oracle), which wraps
ODPI-C (vendored C source, compiled by the crate — build needs only a C
compiler). ODPI-C loads the **Oracle Client library** (`libclntsh`) by
`dlopen` **at runtime**, so:

- the crate **compiles** and the unit tests / `register_profile` run with **no
  Oracle Instant Client installed** (they never open a connection);
- only an actual call (`op: query` / `op: execute`) — and the integration
  test — needs the Instant Client present on the runtime host.

Oracle TLS lives inside the C client layer, so there is no openssl / native-tls
/ rustls dependency here.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `dsn` | string (required) | — | Oracle Easy Connect (`//host:1521/SERVICE`) or a TNS alias. Operator-configured (not caller-templated). The port lives in the dsn. |
| `username` | string (required) | — | Database user. |
| `password` | string (required) | — | A literal, or `${env.X}` / `vault://…` / `${cred://…}` resolved at config load. A bare per-caller `cred://` is **rejected**. |
| `operation` | `query`\|`list_tables`\|`list_columns` | `query` | `query` runs the operator-fixed `query`; the catalog ops introspect the data dictionary (see **Schema discovery**). |
| `query` | string | — | Statement with `:1, :2, …` placeholders. Operator-fixed. Required for `operation: query`; ignored by the catalog ops. |
| `op` | `query`\|`execute` | `query` | `query` → rows; `execute` → rows-affected (committed). `operation: query` only. |
| `params` | `[string]` | `[]` | Ordered CEL expressions; `params[i]` → `:{i+1}`. |
| `owner` | string | — | Catalog ops: static owner/schema filter, bound as `:owner`. Absent → the connected user's schema (`USER`). |
| `table` | string | — | Catalog ops: static table filter, bound as `:tbl`. Required for `list_columns` (via this or `table_arg`). |
| `owner_arg` | string | — | Catalog ops: tool-argument name supplying the owner filter at call time (overrides `owner`). Bound, never interpolated. |
| `table_arg` | string | — | Catalog ops: tool-argument name supplying the table filter at call time (overrides `table`). Bound, never interpolated. |
| `size_limit` | int | `100` | Client-side cap on returned rows (`query`). |
| `timeout_ms` | int | `10000` | Per-call ceiling (connect + statement + read); also set as the ODPI-C call timeout. |
| `pool_max_size` | int | `4` | Maximum pooled connections for this binding. Connections open lazily on first use and are reused across calls. |

### As a tool

```yaml
mcp:
  capabilities:
    tools:
      - name: directory.find_employee
        description: Look up an employee by id.
        input_schema:
          type: object
          properties: { id: { type: integer } }
          required: [id]
        backend:
          kind: oracle
          dsn: "//ora1.corp.example.com:1521/HRPDB1"
          username: "svc_mcpg"
          password: "${env.ORACLE_HR_PASSWORD}"
          op: query
          query: "SELECT id, full_name, email FROM employees WHERE id = :1"
          params: ["arguments.id"]              # bound to :1 — injection-safe
```

### As a write tool (`op: execute`)

```yaml
      backend:
        kind: oracle
        dsn: "//ora1.corp.example.com:1521/HRPDB1"
        username: "svc_mcpg"
        password: "${env.ORACLE_HR_PASSWORD}"
        op: execute
        query: "UPDATE employees SET email = :1 WHERE id = :2"
        params: ["arguments.email", "arguments.id"]
```

## Schema discovery (`operation: list_tables` / `list_columns`)

Set `operation` to introspect the database's structure from Oracle's data
dictionary. These ops run ordinary `SELECT`s against the `ALL_*` views — the
objects the **connected user** may access — so no elevated `DBA_*` /
`SELECT ANY DICTIONARY` privilege is required.

- `list_tables` → `SELECT owner, table_name, tablespace_name FROM all_tables …`
- `list_columns` → `SELECT owner, table_name, column_name, data_type, data_length, nullable, column_id FROM all_tab_columns …`

`query` / `op` / `params` are ignored (catalog ops are inherently read-only
metadata reads). Optional `owner` / `table` filters narrow the result; each is
bound as a `:owner` / `:tbl` SQL parameter — **never** interpolated into the
statement — so a caller-supplied filter can only narrow the metadata. With no
`owner` filter the query defaults to the connected user's current schema
(`owner = USER`). Oracle owners/tables are case-sensitive and stored
upper-cased.

```yaml
      # List the tables in a schema (operator-pinned owner).
      backend:
        kind: oracle
        dsn: "//ora1.corp.example.com:1521/HRPDB1"
        username: "svc_mcpg"
        password: "${env.ORACLE_HR_PASSWORD}"
        operation: list_tables
        owner: "HR"
```

```yaml
      # List a table's columns; the caller picks the table per call.
      backend:
        kind: oracle
        dsn: "//ora1.corp.example.com:1521/HRPDB1"
        username: "svc_mcpg"
        password: "${env.ORACLE_HR_PASSWORD}"
        operation: list_columns
        owner: "HR"             # static owner; bound as :owner
        table_arg: "table"      # arguments.table → bound as :tbl
```

For the catalog ops `output_schema` types `response.rows` to the known
dictionary columns (e.g. `OWNER`, `TABLE_NAME`, `COLUMN_NAME`, `DATA_TYPE`,
`DATA_LENGTH`, `NULLABLE`, `COLUMN_ID`), and `input_schema` surfaces any
configured `owner_arg` / `table_arg` names.

## MCP surfaces & composition

The same binding works on every MCP surface. The surface is selected by the
capability list the binding sits under plus a `surface:` knob; composition is via
`pipeline` steps and child tools.

### As a pipeline step

Inside a `kind: pipeline` binding, an Oracle step uses the `oracle` step
discriminator. The backend config fields are flattened next to `id` / `kind`;
`input_transform` shapes the step's arguments from prior steps.

```yaml
      backend:
        kind: pipeline
        pipeline_timeout_ms: 15000
        steps:
          - id: lookup
            kind: oracle
            dsn: "//ora1.corp.example.com:1521/HRPDB1"
            username: "svc_mcpg"
            password: "${env.ORACLE_HR_PASSWORD}"
            op: query
            query: "SELECT id, full_name, email FROM employees WHERE id = :1"
            params: ["arguments.id"]
            input_transform: "${arguments}"
          - id: summarize
            kind: transform
            expression: "{ 'employee': steps.lookup.response.rows[0] }"
```

### As a resource

Place the binding under `mcp.capabilities.resources[]` with `surface: resource`.
Successful rows are reshaped into the `resources/read` `{contents:[…]}` body. Set
a static `uri:` or let the binding use the requested URI from the read call.

```yaml
  capabilities:
    resources:
      - name: directory.employees
        uri: "oracle://hr/employees"
        backend:
          kind: oracle
          dsn: "//ora1.corp.example.com:1521/HRPDB1"
          username: "svc_mcpg"
          password: "${env.ORACLE_HR_PASSWORD}"
          op: query
          surface: resource
          uri: "oracle://hr/employees"
          query: "SELECT id, full_name, email FROM employees WHERE rownum <= 100"
```

### As a resource template (per-`{id}` read)

Place the binding under `mcp.capabilities.resource_templates[]` with
`surface: resource` and a `uri_template` carrying one or more `{var}` segments.
On a `resources/read` of a concrete URI the gateway extracts each template
variable and supplies it in the call arguments as `arguments.<var>`; set
`read_query` to the single-row read whose `:1, :2, …` placeholders are bound from
`params` (which reference `arguments.<var>`). The extracted value binds
SERVER-SIDE as a query parameter — it is never interpolated into SQL
(injection-safe). `read_query` may stand alone (the `query` statement may be
omitted); it is operator-fixed, must be read-only (SELECT / WITH), and must not
carry a bare `cred://`. The single matched row is reshaped into the
`resources/read` `{contents:[…]}` body keyed on the requested URI.

```yaml
  capabilities:
    resource_templates:
      - name: order.by_id
        uri_template: "oracle://orders/{id}"
        backend:
          kind: oracle
          dsn: "//ora1.corp.example.com:1521/SALESPDB1"
          username: "svc_mcpg"
          password: "${env.ORACLE_SALES_PASSWORD}"
          surface: resource
          read_query: "SELECT * FROM orders WHERE id = :1"
          params: ["arguments.id"]
```

### As a prompt

Under `mcp.capabilities.prompts[]` with `surface: prompt`, rows are reshaped into
the `prompts/get` `{messages:[…]}` body.

```yaml
  capabilities:
    prompts:
      - name: directory.context
        backend:
          kind: oracle
          dsn: "//ora1.corp.example.com:1521/HRPDB1"
          username: "svc_mcpg"
          password: "${env.ORACLE_HR_PASSWORD}"
          op: query
          surface: prompt
          query: "SELECT full_name, email FROM employees WHERE rownum <= 20"
```

### As a child tool

An LLM / generator binding can list this binding in its child-tool set, letting
the model call it during a turn. Child dispatch is governed by
`governance.child_invoke.enforce_gates` (depth cap + self-call cycle refusal
apply). Use an `op: query` binding (read-only) as a child.

### Schemas & annotations

`output_schema` for the envelope wrapper is advertised in `tools/list`, and
`input_schema` is derived from the declared `params`. Operators should mark
read-only (`op: query`) bindings explicitly so clients treat them as
side-effect-free:

```yaml
        annotations: { read_only: true, open_world: false }
```

## Response envelope

```jsonc
{
  "toolName": "directory.find_employee",
  "profile":  "directory.find_employee",
  "request":  { "dsn": "//ora1.corp.example.com:1521/HRPDB1", "op": "query" },
  "response": {                               // op: query
    "rows": [ { "ID": 7, "FULL_NAME": "Alice", "EMAIL": "a@x" } ],
    "count": 1,
    "rowsAffected": null,
    "durationMs": 9
  },
  "downstreamError": null,        // non-null ⇒ isError:true (oracle_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

`op: execute` instead populates `response.rowsAffected` (and `rows`/`count`
are null). Oracle reports unquoted column names upper-cased — alias them in the
`SELECT` if you want a specific case in the JSON keys.

## Security

- **Parameter binding.** Caller data reaches the database only as bound Oracle
  parameters (`:1, …`), never concatenated into the statement — SQL injection
  is structurally impossible. The `query` text is operator-fixed.
- **No plaintext secrets.** The login `password` resolves through the gateway
  secret-resolver (`${env.X}` / `vault://…`); it is never committed.
- **Bare `cred://` not supported.** The connection is one service identity, so
  a bare per-caller `cred://` password is rejected at config validation — use
  a service account + the config secret-resolver.

## Build / test

```bash
nx build mcpg-plugin-backend-oracle
nx test  mcpg-plugin-backend-oracle                                     # unit tests (no Instant Client)
cargo test -p mcpg-plugin-backend-oracle --features integration-tests   # Oracle (docker + Instant Client)
nx lint  mcpg-plugin-backend-oracle
```

## Connection pooling

Each binding keeps a **lazy** `deadpool` connection pool (mirroring the `mssql`
backend). The pool is built at `register_profile` but opens **no** connection
until the first call, so registration and the unit tests stay free of any
ODPI-C call (no Instant Client needed to compile or unit-test). On a call a
connection is drawn from the pool (opening one only when none is idle, up to
`pool_max_size`), the per-call ODPI-C timeout is reapplied, the statement runs
on a blocking thread, and the connection is returned to the pool for reuse.
Recycled connections are pinged with `SELECT 1 FROM dual` before reuse; a dead
session is discarded and a fresh one opened. rust-oracle's own native session
pool was **not** used: it eagerly loads `libclntsh` and opens sessions, which
would force the Instant Client at boot and break the no-client unit tests; the
deadpool wrapper keeps the open lazy.

## Change-watching

A resource can subscribe to Oracle changes through the plugin's second entity —
a **polling `watch_strategy`** (kind `oracle_poll`). Oracle has no native
change-push channel here, so the strategy runs a cheap read-only scalar
**high-water query** (`tracking_query`) on a cadence and emits
`notifications/resources/updated` whenever that scalar advances. The first tick
only records a baseline, so a watcher never fires spuriously at startup.

Attach it under a resource's `watch:` block. The watch carries its own
connection (it is not tied to the binding's profile) plus the tracking query:

```yaml
mcp.configurations[].resources[].watch:
  type: plugin
  kind: oracle_poll
  dsn: "//db.internal:1521/ORCLPDB1"
  username: "svc"
  password: "${env.ORACLE_PW}"
  tracking_query: "SELECT max(updated_at) FROM events"
  interval_ms: 30000
```

**Watch spec fields**

| Field | Type | Default | Description |
|---|---|---|---|
| `dsn` | string | *(required)* | Easy Connect string or TNS alias. Operator-fixed. |
| `username` | string | *(required)* | Database username. |
| `password` | string | *(required)* | Config-resolved (`${env.X}` / `vault://`). A per-caller `cred://` is rejected. |
| `tracking_query` | string | *(required)* | Read-only scalar high-water query; its first-row first-column value is the cursor. |
| `interval_ms` | int | `60000` | Poll cadence (floored at 250 ms). |
| `timeout_ms` | int | `10000` | Per-tick connect + statement + read budget. |

The `tracking_query` is held to a read-only keyword guard (SELECT / WITH); an
empty or non-read-only query is rejected at watch start. A tick returning zero
rows (or a NULL scalar) is treated as "no change"; transient connect / query
failures are logged and retried on the next tick. The watcher uses its own lazy
single-connection `deadpool` pool (no ODPI-C call until the first tick).

## Scope / deferred

- **Per-caller credentials** (per-cred connections) — v1 is one service
  identity per binding.
- **Multi-result-set / REF CURSOR / output parameters** — v1 returns the rows
  of the statement (`query`) or the rows-affected total (`execute`).
- **Rich type fidelity.** Large `NUMBER`s and temporal types are projected as
  strings (full fidelity); BLOB / RAW are base64. CLOB / NCLOB are read as
  text.
