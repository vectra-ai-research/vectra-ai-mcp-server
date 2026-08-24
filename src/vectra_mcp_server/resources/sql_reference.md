# Vectra AI SQL Search — MCP Resource

## 1. Overview

Use this resource when you need to construct or hand-edit a SQL string before submitting it to the MCP tool.

## 2. Data Sources & Fully-Qualified Table Names

The dialect uses 3-part table names: `<data_source>.<stream>.<source_id>`. For investigations, always use the special source ID `_all`.

| Data source | Description | Tables (fully-qualified) |
|---|---|---|
| `network` | network telemetry | `network.beacon._all`, `network.dce_rpc._all`, `network.dhcp._all`, `network.dns._all`, `network.http._all`, `network.isession._all`, `network.kerberos._all`, `network.ldap._all`, `network.match._all` (Suricata), `network.ntlm._all`, `network.radius._all`, `network.rdp._all`, `network.smb_files._all`, `network.smb_mapping._all`, `network.ssh._all`, `network.ssl._all`, `network.x509._all` |
| `o365` (a.k.a. `m365`) | Microsoft 365 audit | `m365.active_directory._all`, `m365.exchange._all`, `m365.general._all`, `m365.sharepoint._all`, `m365.directory_audits._all`, `m365.signins._all` |
| `aws` | AWS CloudTrail | `aws.cloudtrail._all` |
| `azurecp` | Azure control-plane | `azurecp.operations._all`, `azurecp.flowlogs._all` |

Notes:
- `_all` IS MANDATORY for natural-language queries; the validator will auto-append it if missing on supported tables.
- The legacy/internal physical names (e.g. `auditazureactivedirectory`, `httpsessioninfo`, `cloudtrail`) map to the qualified names above.

## 3. Supported SQL Syntax

### 3.1 Statement shape

Only a single `SELECT` statement, with this overall shape:

```sql
SELECT [DISTINCT | ALL] <select_items>
FROM <table>                       -- single table; UNION allowed only for one specific pair (see §3.7)
[WHERE  <boolean_expression>]
[GROUP BY <grouping_elements>]
[HAVING <boolean_expression>]
[ORDER BY <sort_items>]
[LIMIT  <integer>]
```

### 3.2 Allowed operators

```
=  !=  <>  <  <=  >  >=
AND  OR  NOT
IS NULL  IS NOT NULL
IN ( ... )                         -- list literal only; no IN (SELECT ...)
LIKE 'pattern'                     -- % and _ wildcards
BETWEEN <lo> AND <hi>
+  -  *  /  %                      -- arithmetic
```

### 3.3 Allowed functions

Aggregations: `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, `STDDEV`, `STDDEV_SAMP`, `STDDEV_POP`, `APPROX_PERCENTILE`, `APPROX_DISTINCT`, `ARRAY_AGG`.

Strings: `LOWER`, `UPPER`, `LENGTH`, `CONCAT`, `SUBSTR`, `SUBSTRING`, `SPLIT`, `SPLIT_PART`, `STRPOS`, `REPLACE`, `REVERSE`, `TRIM`, `COALESCE`, `NULLIF`.

Regex (Trino-style, **2 args only** for `REGEXP_LIKE`): `REGEXP_LIKE`, `REGEXP_EXTRACT`, `REGEXP_EXTRACT_ALL`, `REGEXP_COUNT`, `REGEXP_POSITION`, `REGEXP_REPLACE`, `REGEXP_SPLIT`.

Date/time: `NOW`, `DATE`, `DATE_ADD`, `DATE_DIFF`, `DATE_TRUNC`, `FROM_ISO8601_TIMESTAMP`, `FROM_UNIXTIME`, `TO_UNIXTIME`.

Arrays / lambdas: `ARRAY_AGG`, `CARDINALITY`, `CONTAINS`, `ANY_MATCH`, `ALL_MATCH` (with `x -> predicate(x)` lambdas).

JSON: `JSON_EXTRACT`, `JSON_EXTRACT_SCALAR`, `JSON_ARRAY_LENGTH`, `JSON_ARRAY_CONTAINS`, `JSON_FORMAT`, `JSON_PARSE`, `JSON_SIZE`.

Misc: `ABS`, `CAST`, `TRY_CAST`, `DISTINCT`.

### 3.4 Allowed expressions

- `CASE WHEN ... THEN ... ELSE ... END` (searched and simple forms)
- `CAST(expr AS TYPE)` and `TRY_CAST(expr AS TYPE)` — supported types include `INTEGER`, `DOUBLE`, `BOOLEAN`, `DATE`, `TIMESTAMP`, `VARCHAR`, `IPADDRESS`
- Dotted field access on nested objects: `id.orig_h`, `status.error_code`, `device_detail.browser`
- Array element access via `array_agg`, `CONTAINS(array_col, value)`
- Quoted column aliases: `COUNT(*) AS "failure_count"`

### 3.5 ABSOLUTELY FORBIDDEN

Validators reject queries containing any of:

- SQL comments — `--` or `/* ... */`. **Not rejected by the API** (probed live
  2026-08-23: a query containing `--` completed and returned rows). They are
  stripped by this server before submission, because `run_investigation`
  normalises whitespace and joining the lines would let a comment swallow every
  clause after it — including the `LIMIT`, leaving the query unbounded. Do not
  put comments in a query; if one slips through it is removed, not honoured.
- `JOIN` of any kind
- CTEs / `WITH` clauses
- Subqueries — anything matching `FROM (SELECT ...)`, `IN (SELECT ...)`, `EXISTS (...)`, etc.
- `UNION` — except the single allowed pair below
- DDL/DML: `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`, `ALTER`, `MERGE`, `TRUNCATE`, etc.

### 3.6 Required conventions

- Every query must be a `SELECT`.
- Always include a sensible `LIMIT` (typical defaults: `100`, sometimes `1000`/`10000`).
- Default time window is **last 14 days**; "last week" → 7 days; "recent" → 3 days.
- Always filter by `timestamp` (every table has a `timestamp` column).
- Prefer aggregating with `GROUP BY` on the most meaningful identity columns (e.g. `id.orig_h`, `username`, `query`, `service`).
- Use SELECT-list aliases in `ORDER BY`, but **not** in `GROUP BY` or `HAVING` (use the underlying expression there).
- Bias toward the table's default columns; only `SELECT *` for forensic detail queries.

### 3.7 The single allowed UNION

A top-level `UNION` is allowed **only** between exactly:

```
network.ntlm._all  UNION  network.kerberos._all
```

Each side must be a plain SELECT from its base table. Any other UNION (nested, more than two terms, other tables) is rejected.

### 3.8 Time-window patterns

```sql
-- Default 14 days
WHERE timestamp BETWEEN date_add('day', -14, now()) AND now()
WHERE timestamp > date_add('day', -14, DATE(NOW()))

-- Last 7 days
WHERE timestamp BETWEEN date_add('day', -7, now()) AND now()

-- Last day / last hour
WHERE timestamp >= date_add('day',  -1, now())
WHERE timestamp >= date_add('hour', -1, now())

-- Explicit ISO range
WHERE timestamp BETWEEN from_iso8601_timestamp('2023-03-29T15:44:15.989585')
                    AND from_iso8601_timestamp('2023-04-05T15:44:15.989585')

-- Late-night hours (00:00–05:59)
AND DATE_DIFF('hour', DATE(timestamp), timestamp) BETWEEN 0 AND 5
```

### 3.9 CIDR / IP filtering

`CONTAINS('<cidr>', TRY_CAST(<ip_col> AS IPADDRESS))` is the only supported way to filter by IP range:

```sql
AND NOT contains('10.0.0.0/8',     TRY_CAST(source_ip_address AS IPADDRESS))
AND NOT contains('172.16.0.0/12',  TRY_CAST(source_ip_address AS IPADDRESS))
AND NOT contains('192.168.0.0/16', TRY_CAST(source_ip_address AS IPADDRESS))
```

### 3.10 Unix-time millisecond columns

Some columns (notably `network.x509._all.certificate.not_valid_before` / `not_valid_after`) are integer milliseconds since epoch. Convert with `from_unixtime(col / 1000)`.

---

## 4. Examples (curated from the repo's prompt set)

All examples below are validated, production prompt examples taken from `src/vectra/nl2sql/example_queries.py`. They cover every supported data source and the most common analytical patterns.

### 4.1 Network — authentication & lateral movement

Hosts with many failed Kerberos pre-auths (brute force / sprays):

```sql
SELECT
    id.orig_h AS source_ip,
    client,
    count(*) AS "failure_count"
FROM network.kerberos._all
WHERE request_type = 'AS'
  AND LOWER(service) LIKE '%krbtgt%'
  AND error_msg IN ('KDC_ERR_C_PRINCIPAL_UNKNOWN', 'KDC_ERR_PREAUTH_FAILED', 'KDC_ERR_CLIENT_REVOKED')
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY id.orig_h, client
HAVING count(*) > 20
ORDER BY "failure_count" DESC
LIMIT 100
```

Late-night successful Kerberos auths:

```sql
SELECT
    id.orig_h AS source_ip,
    client,
    service,
    count(*) AS "auth_count"
FROM network.kerberos._all
WHERE success = TRUE
  AND DATE_DIFF('hour', DATE(timestamp), timestamp) BETWEEN 0 AND 5
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY id.orig_h, client, service
HAVING count(*) > 5
ORDER BY "auth_count" DESC
LIMIT 100
```

Failed NTLM logins across multiple hosts:

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    username,
    domain,
    COUNT(*) AS "failure_count"
FROM network.ntlm._all
WHERE success = FALSE
  AND timestamp BETWEEN date_add('day', -1, now()) AND now()
GROUP BY id.orig_h, orig_hostname, username, domain
HAVING COUNT(*) > 5
ORDER BY "failure_count" DESC
LIMIT 100
```

Scattered Spider hunting — the **only allowed UNION** pattern:

```sql
SELECT 'NTLM' AS activity_type, orig_hostname, username, domain, COUNT(*) AS count
FROM network.ntlm._all
WHERE success = FALSE
  AND timestamp BETWEEN date_add('day', -14, now()) AND now()
GROUP BY id.orig_h, orig_hostname, username, domain
HAVING COUNT(*) > 10

UNION

SELECT 'Kerberos' AS activity_type, orig_hostname, client AS username, service AS domain, COUNT(*) AS count
FROM network.kerberos._all
WHERE success = FALSE
  AND (error_msg = 'KDC_ERR_PREAUTH_FAILED' OR error_code = '24')
  AND timestamp BETWEEN date_add('day', -14, now()) AND now()
GROUP BY id.orig_h, orig_hostname, client, service
HAVING COUNT(*) > 10

ORDER BY count DESC
LIMIT 100
```

### 4.2 Network — DNS

DNS connections to Russian TLDs in the last hour (regex on hostname):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname.name AS source_hostname,
    query AS russian_domain,
    COUNT(*) AS query_count
FROM network.dns._all
WHERE timestamp >= date_add('hour', -1, now())
  AND REGEXP_LIKE(query, '\.ru$')
GROUP BY id.orig_h, orig_hostname.name, query
ORDER BY query_count DESC
LIMIT 100
```

Long DNS TXT queries (potential exfil):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    query,
    count(*) AS "query_count",
    sum(total_answers) AS "total_answers",
    avg(LENGTH(query)) AS "avg_query_length"
FROM network.dns._all
WHERE qtype_name = 'TXT'
  AND LENGTH(query) > 50
  AND timestamp BETWEEN date_add('day', -7, now()) AS now()
GROUP BY id.orig_h, orig_hostname, query
HAVING count(*) > 10
ORDER BY "avg_query_length" DESC
LIMIT 100
```

### 4.3 Network — HTTP

Suspicious user agents (allow-list approach):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    user_agent,
    count(*) AS "request_count"
FROM network.http._all
WHERE user_agent NOT LIKE '%Chrome%'
  AND user_agent NOT LIKE '%Firefox%'
  AND user_agent NOT LIKE '%Safari%'
  AND user_agent NOT LIKE '%Edge%'
  AND LENGTH(user_agent) > 0
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY id.orig_h, orig_hostname, user_agent
ORDER BY "request_count" DESC
LIMIT 100
```

Large outbound POSTs (potential data smuggling):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    host,
    uri,
    request_body_len,
    timestamp
FROM network.http._all
WHERE method = 'POST'
  AND request_body_len > 100000
  AND host NOT LIKE '%microsoft.com'
  AND host NOT LIKE '%office.com'
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
ORDER BY request_body_len DESC
LIMIT 100
```

Log4Shell exploitation patterns:

```sql
SELECT *
FROM network.http._all
WHERE (uri LIKE '%${jndi:%'
       OR uri LIKE '%${lower%'
       OR uri LIKE '%${${env%'
       OR uri LIKE '%${${::-j%')
  AND local_orig = false
  AND timestamp BETWEEN date_add('day', -14, now()) AND now()
LIMIT 100
```

### 4.4 Network — SSL/TLS & X.509

Weak ciphers in use:

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    cipher,
    server_name,
    count(*) AS "connection_count"
FROM network.ssl._all
WHERE (cipher LIKE '%RC4%'
       OR cipher LIKE '%DES%'
       OR cipher LIKE '%3DES%'
       OR cipher LIKE '%NULL%'
       OR cipher LIKE '%AES_128_CBC%')
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY id.orig_h, orig_hostname, cipher, server_name
ORDER BY "connection_count" DESC
LIMIT 100
```

Certificates expiring in next 30 days (millisecond-epoch column):

```sql
SELECT *
FROM network.x509._all
WHERE local_resp = true
  AND from_unixtime(certificate.not_valid_after / 1000) > now()
  AND from_unixtime(certificate.not_valid_after / 1000) < date_add('day', 30, now())
LIMIT 100
```

Certificates with unusually short validity (uses `date_diff` on derived timestamps):

```sql
SELECT
  certificate.subject,
  certificate.issuer,
  from_unixtime(certificate.not_valid_before / 1000) AS not_valid_before_ts,
  from_unixtime(certificate.not_valid_after  / 1000) AS not_valid_after_ts,
  date_diff('day',
            from_unixtime(certificate.not_valid_before / 1000),
            from_unixtime(certificate.not_valid_after  / 1000)) AS validity_days,
  array_agg(DISTINCT application) AS "applications"
FROM network.x509._all
WHERE date_diff('day',
                from_unixtime(certificate.not_valid_before / 1000),
                from_unixtime(certificate.not_valid_after  / 1000)) < 30
  AND from_unixtime(certificate.not_valid_before / 1000) > date_add('day', -90, now())
  AND "timestamp" BETWEEN date_add('day', -7, now()) AND now()
GROUP BY certificate.subject, certificate.issuer,
         certificate.not_valid_before, certificate.not_valid_after
ORDER BY validity_days ASC
LIMIT 100
```

### 4.5 Network — sessions / volumes / scanning

Hosts moving > 1 GiB in 5 days (uses `HAVING SUM(...)`):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname.name AS source_hostname,
    id.resp_h AS dest_ip,
    resp_hostname.name AS dest_hostname,
    SUM(orig_ip_bytes) AS total_orig_bytes,
    SUM(resp_ip_bytes) AS total_resp_bytes
FROM network.isession._all
WHERE timestamp >= date_add('day', -5, now())
GROUP BY id.orig_h, orig_hostname.name, id.resp_h, resp_hostname.name
HAVING SUM(orig_ip_bytes) > 1073741824
    OR SUM(resp_ip_bytes) > 1073741824
ORDER BY total_orig_bytes DESC
LIMIT 100
```

Port-scan detection (many distinct destination ports with `S0`/`REJ`):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    count(DISTINCT id.resp_h) AS "targets",
    count(DISTINCT id.resp_p) AS "ports",
    count(*) AS "connection_count"
FROM network.isession._all
WHERE conn_state IN ('S0', 'REJ')
  AND timestamp BETWEEN date_add('day', -1, now()) AND now()
GROUP BY id.orig_h, orig_hostname
HAVING count(DISTINCT id.resp_p) > 10
ORDER BY "ports" DESC
LIMIT 100
```

Behavioural baseline using `CASE` + `SUM(CAST(... AS INTEGER))` to bucket recent vs prior windows:

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname.name AS source_hostname,
    service,
    SUM(CAST((timestamp BETWEEN date_add('day', -1, now())  AND now()) AS INTEGER))                                                  AS "recent_count",
    SUM(CAST((timestamp BETWEEN date_add('day', -14, now()) AND date_add('day', -1, now())) AS INTEGER))                              AS "previous_count",
    SUM(CAST((timestamp BETWEEN date_add('day', -1, now())  AND now()) AS INTEGER))
      - SUM(CAST((timestamp BETWEEN date_add('day', -14, now()) AND date_add('day', -1, now())) AS INTEGER))/13                     AS "delta"
FROM network.isession._all
WHERE service IS NOT NULL
  AND timestamp BETWEEN date_add('day', -14, now()) AND now()
GROUP BY id.orig_h, orig_hostname.name, service
HAVING SUM(CAST((timestamp BETWEEN date_add('day', -1, now()) AND now()) AS INTEGER)) > 0
ORDER BY "delta" DESC
LIMIT 200
```

### 4.6 Network — SMB & files (regex extraction)

Least-common file extensions accessed (uses `REGEXP_EXTRACT` and `array_agg`):

```sql
SELECT
    REGEXP_EXTRACT(name, '\.([^\.]+)') AS file_extension,
    COUNT(*) AS "count",
    array_agg(DISTINCT orig_hostname) AS "accessing_hosts"
FROM network.smb_files._all
WHERE name LIKE '%.%'
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY REGEXP_EXTRACT(name, '\.([^\.]+)')
ORDER BY "count" ASC
LIMIT 100
```

Sensitive file access:

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    path,
    name,
    action,
    count(*) AS "access_count"
FROM network.smb_files._all
WHERE (name LIKE '%password%' OR name LIKE '%secret%' OR name LIKE '%key%'
       OR name LIKE '%cred%' OR name LIKE '%config%' OR name LIKE '%.kdbx')
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY id.orig_h, orig_hostname, path, name, action
ORDER BY "access_count" DESC
LIMIT 100
```

### 4.7 Network — Suricata (`network.match._all`)

Alerts grouped by signature (deeply-nested fields):

```sql
SELECT
  alert.signature_id   AS "alert_signature_id",
  alert.signature      AS "alert_signature",
  alert.metadata.signature_severity AS "alert_metadata_signature_severity",
  COUNT(*)             AS "Hits"
FROM network.match._all
WHERE timestamp > date_add('hour', -48, now())
GROUP BY alert.signature_id, alert.signature, alert.metadata.signature_severity
ORDER BY "Hits" DESC
LIMIT 100
```

### 4.8 Network — `CONTAINS` for arrays and CIDRs

Array membership (string array column):

```sql
SELECT
    id.orig_h AS source_ip,
    orig_hostname,
    attributes,
    count(*) AS "request_count"
FROM network.ldap._all
WHERE (CONTAINS(attributes, 'userCertificate')
    OR CONTAINS(attributes, 'thumbnailPhoto')
    OR CONTAINS(attributes, 'jpegPhoto')
    OR CONTAINS(attributes, 'objectGUID')
    OR CONTAINS(attributes, 'objectSid'))
  AND timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY id.orig_h, orig_hostname, attributes
ORDER BY "request_count" DESC
LIMIT 100
```

CIDR membership (note `TRY_CAST` to `IPADDRESS`):

```sql
SELECT timestamp, beacon_uid, orig_hostname, id.orig_h AS source_ip
FROM network.beacon._all
WHERE NOT contains('1.1.1.0/24', TRY_CAST(id.orig_h AS IPADDRESS))
  AND timestamp > date_add('hour', -6, now())
ORDER BY timestamp DESC
LIMIT 100
```

### 4.9 Microsoft 365 (o365)

Per-user audit trail (all events in last 30 days):

```sql
SELECT *
FROM m365.active_directory._all
WHERE lower(user_id) = '<user@mycompany.com>'
  AND timestamp > date_add('day', -30, DATE(NOW()))
```

Failed AAD logins per user:

```sql
SELECT lower(user_id) AS userPrincipalName,
       count(*)        AS count,
       min(creation_time) AS fromDate,
       max(creation_time) AS toDate
FROM m365.active_directory._all
WHERE operation = 'UserLoginFailed'
  AND timestamp > date_add('day', -14, DATE(NOW()))
GROUP BY user_id
LIMIT 100
```

Sign-ins where MFA was skipped (deeply nested + `IN` + `BETWEEN CAST(...)`):

```sql
SELECT
    creation_time,
    user_principal_name,
    user_display_name,
    client_ip,
    location.country_or_region,
    location.city,
    device_detail.device_id,
    device_detail.operating_system,
    device_detail.browser,
    app_display_name,
    status.additional_details
FROM m365.signins._all
WHERE status.error_code = 0
  AND status.additional_details IN (
        'MFA requirement skipped due to registered device',
        'MFA requirement skipped due to IP address',
        'MFA requirement skipped due to app password',
        'MFA requirement skipped due to ADFS-issued InsideCorpNet claim; tenant was configured to skip MFA if this claim is present',
        'MFA requirement skipped due to remembered device'
    )
  AND timestamp BETWEEN CAST('2023-03-29' AS DATE) AND CAST('2023-04-05' AS DATE)
ORDER BY creation_time DESC
LIMIT 100
```

PowerShell sign-ins (uses `from_iso8601_timestamp` + `REGEXP_LIKE`):

```sql
SELECT user_principal_name AS userName,
       user_display_name   AS displayName,
       COUNT(*)            AS loginCount,
       MIN(creation_time)  AS firstLogin,
       MAX(creation_time)  AS lastLogin
FROM m365.signins._all
WHERE status.error_code = 0
  AND REGEXP_LIKE(app_display_name, 'powershell')
  AND timestamp BETWEEN from_iso8601_timestamp('2023-03-29T15:44:15.989585')
                    AND from_iso8601_timestamp('2023-04-05T15:44:15.989585')
GROUP BY user_principal_name, user_display_name
ORDER BY loginCount DESC
LIMIT 10000
```

Application consent grants:

```sql
SELECT count(*) AS count,
       min(creation_time) AS fromDate,
       max(creation_time) AS toDate
FROM m365.directory_audits._all
WHERE activity_display_name IN ('Consent to application', 'Grant contextual consent to application')
  AND timestamp BETWEEN date_add('day', -14, now()) AND now()
LIMIT 100
```

### 4.10 AWS CloudTrail

Root account activity (last 30 days):

```sql
SELECT *
FROM aws.cloudtrail._all
WHERE user_identity.type = 'Root'
  AND timestamp > date_add('day', -30, DATE(NOW()))
```

Failed API calls from external IPs (CIDR exclusion):

```sql
SELECT user_identity.arn,
       source_ip_address,
       event_name,
       error_code,
       error_message,
       count(*)            AS failure_count,
       min(event_time)     AS fromDate,
       max(event_time)     AS toDate
FROM aws.cloudtrail._all
WHERE error_code IS NOT NULL
  AND NOT contains('10.0.0.0/8',     TRY_CAST(source_ip_address AS IPADDRESS))
  AND NOT contains('172.16.0.0/12',  TRY_CAST(source_ip_address AS IPADDRESS))
  AND NOT contains('192.168.0.0/16', TRY_CAST(source_ip_address AS IPADDRESS))
  AND source_ip_address != 'AWS_INTERNAL'
  AND timestamp > date_add('day', -7, DATE(NOW()))
GROUP BY user_identity.arn, source_ip_address, event_name, error_code, error_message
LIMIT 100
```

IAM administrative actions:

```sql
SELECT user_identity.arn,
       event_name,
       aws_region,
       source_ip_address,
       count(*)        AS action_count,
       min(event_time) AS fromDate,
       max(event_time) AS toDate
FROM aws.cloudtrail._all
WHERE event_source = 'iam.amazonaws.com'
  AND event_name IN ('CreateUser','DeleteUser','CreateRole','DeleteRole',
                     'AttachUserPolicy','DetachUserPolicy','AttachRolePolicy','DetachRolePolicy',
                     'CreatePolicy','DeletePolicy','PutUserPolicy','DeleteUserPolicy')
  AND timestamp > date_add('day', -30, DATE(NOW()))
GROUP BY user_identity.arn, event_name, aws_region, source_ip_address
ORDER BY action_count DESC
LIMIT 100
```

`AssumeRole` (privilege escalation surveillance):

```sql
SELECT user_identity.arn,
       assume_role_role_arn,
       source_ip_address,
       aws_region,
       count(*)        AS assume_count,
       min(event_time) AS fromDate,
       max(event_time) AS toDate
FROM aws.cloudtrail._all
WHERE event_name = 'AssumeRole'
  AND error_code IS NULL
  AND timestamp > date_add('day', -14, DATE(NOW()))
GROUP BY user_identity.arn, assume_role_role_arn, source_ip_address, aws_region
HAVING count(*) > 1
ORDER BY assume_count DESC
LIMIT 100
```

### 4.11 Azure (`azurecp`)

Privileged ops from external IPs:

```sql
SELECT actor.name,
       calleripaddress,
       operationname,
       count(*)    AS operation_count,
       min(time)   AS fromDate,
       max(time)   AS toDate
FROM azurecp.operations._all
WHERE operationname IN (
        'Microsoft.Authorization/roleAssignments/write',
        'Microsoft.Authorization/roleDefinitions/write',
        'Microsoft.Resources/subscriptions/resourceGroups/write',
        'Microsoft.Compute/virtualMachines/write')
  AND NOT contains('10.0.0.0/8',     TRY_CAST(calleripaddress AS IPADDRESS))
  AND NOT contains('172.16.0.0/12',  TRY_CAST(calleripaddress AS IPADDRESS))
  AND NOT contains('192.168.0.0/16', TRY_CAST(calleripaddress AS IPADDRESS))
  AND calleripaddress IS NOT NULL
  AND resulttype = 'Success'
  AND timestamp > date_add('day', -7, DATE(NOW()))
GROUP BY actor.name, calleripaddress, operationname
ORDER BY operation_count DESC
LIMIT 100
```

Resource deletions:

```sql
SELECT actor.name,
       operationname,
       resourcegroup,
       calleripaddress,
       count(*)   AS deletion_count,
       min(time)  AS fromDate,
       max(time)  AS toDate
FROM azurecp.operations._all
WHERE operationname LIKE '%/delete'
  AND resulttype = 'Success'
  AND timestamp > date_add('day', -7, DATE(NOW()))
GROUP BY actor.name, operationname, resourcegroup, calleripaddress
ORDER BY deletion_count DESC
LIMIT 100
```

Top denied flow-log rules (NSG flow logs):

```sql
SELECT rule,
       COUNT(*)         AS denied_flows,
       MIN(timestamp)   AS first_seen,
       MAX(timestamp)   AS last_seen
FROM azurecp.flowlogs._all
WHERE UPPER(flowstate) = 'D'
  AND rule IS NOT NULL
GROUP BY rule
ORDER BY denied_flows DESC
LIMIT 20
```

Specific source talking to whom (Azure flowlogs):

```sql
SELECT dstip   AS peer_ip,
       dstport AS peer_port,
       protocol,
       COUNT(*) AS flow_records
FROM azurecp.flowlogs._all
WHERE timestamp >= DATE_ADD('day', -3, NOW())
  AND srcip = '192.168.1.10'
  AND UPPER(flowstate) != 'D'
GROUP BY dstip, dstport, protocol
LIMIT 100
```

Bounded by an explicit timestamp window:

```sql
SELECT dstip AS peer_ip,
       COUNT(*) AS flow_records
FROM azurecp.flowlogs._all
WHERE timestamp >= FROM_ISO8601_TIMESTAMP('2023-10-12T09:00:00Z')
  AND timestamp <  FROM_ISO8601_TIMESTAMP('2023-10-12T11:00:00Z')
  AND srcip = '1.2.3.4'
  AND UPPER(flowstate) != 'D'
GROUP BY dstip
ORDER BY flow_records DESC
```

KeyVault interactions for a specific actor:

```sql
SELECT operationname, resourcegroup, resulttype,
       count(*)  AS operation_count,
       min(time) AS first_seen,
       max(time) AS last_seen
FROM azurecp.operations._all
WHERE lower(actor.name) = 'X@mycompany.com'
  AND lower(resourceid) LIKE '%microsoft.keyvault%'
  AND timestamp > date_add('day', -1, DATE(NOW()))
GROUP BY operationname, resourcegroup, resulttype
ORDER BY last_seen DESC
LIMIT 100
```

---

## 5. Cheatsheet — common building blocks

```sql
-- Time
date_add('day', -14, now())                                  -- 14 days ago, timestamp
date_add('hour', -1, now())                                  -- 1 hour ago
date_add('day', -30, DATE(NOW()))                            -- 30 days ago, midnight
from_iso8601_timestamp('2023-10-12T09:00:00Z')               -- ISO literal
from_unixtime(epoch_ms / 1000)                               -- ms epoch -> timestamp
date_diff('day', start_ts, end_ts)                           -- difference in days

-- Strings
LOWER(col) = 'value'
col LIKE '%substring%'
REGEXP_LIKE(col, 'pattern')                                  -- 2 args ONLY
REGEXP_EXTRACT(name, '\.([^\.]+)')                           -- capture group
LENGTH(col) > 50

-- Sets
col IN ('a','b','c')
col NOT IN ('a','b','c')
col BETWEEN 1 AND 10

-- Aggregates with HAVING (use the expression, not the alias)
GROUP BY id.orig_h, orig_hostname
HAVING COUNT(*) > 10

-- Distinct counts
COUNT(DISTINCT id.resp_h)

-- Arrays
array_agg(DISTINCT col) AS "values"
CONTAINS(array_col, 'value')

-- IPs / CIDR
NOT contains('10.0.0.0/8', TRY_CAST(ip_col AS IPADDRESS))

-- Booleans / null safety
col IS NOT NULL
status.error_code = 0
success = TRUE
```

---

## 6. Output contract (if your MCP tool wraps the LLM agent)

The Vectra agent returns one of two JSON shapes (see `src/vectra/nl2sql/prompts/trino_assistant.py`). If your MCP tool returns SQL directly, you can ignore the LLM wrapper, but if you proxy the agent, expect:

```json
// Success
{
  "type": "Success",
  "reasoning": "…explanation in the analyst's language…",
  "suggestions": "…two **bolded** follow-up ideas…",
  "query": "SELECT … FROM … LIMIT 100"
}

// Invalid
{
  "type": "InvalidRequest",
  "category": "out_of_scope" | "sql_limitations" | "insufficient_metadata" | "other",
  "error_message": "…short reason…"
}
```