# CyberSentinel Desktop Security Monitoring

Version 0.3 adds a local security-monitoring workflow alongside the existing assessment modules. It opens directly to the dashboard and does not add a login page or web interface.

## What is implemented

| Capability | Desktop implementation |
| --- | --- |
| Collection | File import and incremental watched files; Windows export helper |
| Normalization | UTC timestamp, server asset, source IP, user, kind, event code, request, status and structured details |
| Search | SQLite FTS5 text terms, exact asset/IP/user/kind filters, UTC range, paging and JSON export |
| Detection | Repeated failures, fixed-threshold request rates, suspicious URL patterns, successful logon after failures and local indicator matches |
| Correlation | Related alerts grouped by server asset/source identity and nearby event time; local risk weights capped at 100 |
| Investigation | Evidence-backed event timeline, owner, state, reasoned resolution and case audit |
| Assessment context | Existing scan findings linked by canonical asset and explicit aliases |
| Intelligence | Local IP/domain lists, JSON/CSV indicator import and optional existing Ollama model advice |
| Automation | Internal triage checklist and evidence export; desktop notification opt-in |
| Reporting | Incident JSON, escaped HTML and PDF; monitoring counts, asset/kind tables and hourly event chart |
| Recovery | Monitoring tables are included in the existing consistent workspace backup/restore |

## First use

1. Open **Security Monitoring → Events & Search**.
2. Enter the server hostname or IP. This is the affected server, not the remote client IP. Windows `Computer` / `MachineName` fields take precedence when available.
3. Select **Import log export** and choose a file you are authorized to inspect.
4. Review the import summary. Malformed records and missing/ambiguous timestamps are reported, not treated as successful checks. See **Log Sources** for recent import details.
5. Review **Alerts**, then choose **Open related incident**.
6. In **Incidents**, inspect the event timeline, rule explanation and linked scan findings. Assign an owner and document the investigation. Contained, resolved and false-positive states require a note.
7. Generate an incident report or export the full JSON evidence. The report library lists the generated files.

The application cannot obtain a website's private server logs from its public URL. Import logs exported by the authorized server administrator or from systems you control. A public website configuration check and server-log monitoring are different data sources.

## Supported log formats

- Apache/Nginx common and combined access logs, including a timestamp such as `[14/Oct/2026:12:30:00 +0530]`.
- Nginx structured JSON/JSONL with `time_iso8601`, `remote_addr`, `request_method`, `request_uri` and `status`.
- Windows XML exports containing `<Event>` / `<Events>`, including named `EventData` fields and UTC `SystemTime`.
- Windows JSON arrays or JSONL with `Id` / `EventID`, `TimeCreated`, `MachineName` / `Computer`, and named `EventData` fields. An `Xml` field containing `Event.ToXml()` is also accepted.
- Windows CSV with those column names. `EventData` can contain a JSON object. `IpAddress`, `TargetUserName` and `UserName` columns are also recognized.
- Native `.evtx` files through the bundled python-evtx parser. Corrupt or unsupported records are reported as errors.
- RFC 5424 syslog with explicit ISO timestamps. SSH failed/accepted-password messages are normalized for login correlation. Legacy RFC 3164 timestamps without a year or offset are deliberately not guessed.
- Explicit normalized JSON can carry other kinds such as firewall events. There is no automatic parser for every firewall vendor's proprietary format.

BOM-marked UTF-16 Windows text exports and UTF-8 exports are accepted for snapshot imports. Live watched text files require UTF-8. Naive timestamps without timezone information are rejected. Timestamps are stored in UTC. Files are limited to 128 MB and 100,000 records per import; individual line-based records are limited to 256 KB.

### Export Windows events

From PowerShell in the project directory:

```powershell
.\scripts\export_windows_events.ps1 -LogName System -MaxEvents 1000 -OutputPath "$env:USERPROFILE\Desktop\windows_events.xml"
```

Use `-LogName Security` for authentication events; Windows permissions may require an elevated shell. The helper only reads events and writes the requested export. It is not automatically run by CyberSentinel.

Windows 4625/4624 events need usable source-IP or account fields for identity correlation. CSV exports containing only a rendered message may not provide those fields. Such records remain searchable, but unidentified failures are not combined into a fabricated actor.

## Detection defaults

| Rule | Default |
| --- | --- |
| Repeated authentication failures | 5 failures in 300 seconds, same asset/source/user identity |
| Request volume | 100 requests in 60 seconds, same asset/client IP |
| Suspicious URL | 1 traversal, script-like, SQL-like or sensitive-path pattern in 300 seconds |
| Success after failures | A successful logon following 5 failures in 300 seconds for the same identity |
| Indicator match | Exact local IP or domain match |

Web 401 responses on login/auth routes are candidates for failed-authentication counting. An HTTP 200 response is not assumed to mean a successful login. Successful-logon correlation uses explicit Windows or parsed authentication events.

Rules are configurable in **Detection Rules**. Request-rate detection uses a fixed threshold, not a learned behavioral baseline. Pattern matches do not establish SQL injection, XSS or successful exploitation. Risk weights are deterministic prioritization values, not attack probabilities or CVSS scores.

Re-evaluation retains historical alerts and case notes, deduplicates overlapping episodes, and preserves the original rule snapshot. New later evidence can reopen a resolved/false-positive case. Disabling a rule does not erase prior evidence.

## Live watched files

In **Log Sources**, register an access log, RFC 5424 syslog file or JSONL file and its asset. Choose whether to read existing content or start at the current end. Enable **Monitor watched files while this app is open**.

Sources are polled every three seconds, with at most 4 MB read from each source per poll. Checkpoints persist across restarts. Incomplete final lines wait for a newline. Rotation, truncation and changed prefixes reset collection; source errors are visible. Snapshot CSV/XML/EVTX files use manual import rather than unsafe assumptions about incremental binary/XML updates.

Repeated imports of the same unchanged file deduplicate by source identity/position/content. Windows exports with channel, computer, record ID and timestamp also deduplicate overlapping exports. Access-log copies under different source identities can be counted separately; avoid importing overlapping copied archives as independent sources.

Monitoring stops when the desktop application closes. It is not an unattended Windows service. Detection runs have a two-minute processing budget; cancellation/timeouts retain imported records and previous alerts rather than claiming complete coverage.

## Threat indicators and asset aliases

Indicator files contain rows/objects with `type` (`ip` or `domain`), `value`, and optional `label`. Import JSON arrays or CSV lists up to 2 MB / 10,000 entries. Invalid rows are reported. Matching is exact; there is no implicit subdomain, CIDR or reputation inference and no external intelligence feed is downloaded automatically.

Aliases declare known hostname/IP equivalences. They apply to new imports and assessment-context matching. Existing event assets are not silently rewritten. Scan links are context, not evidence that a discovered weakness caused an incident.

## Safety and deployment limits

No monitoring rule executes a shell command, blocks an IP, disables an account or changes a remote system. The triage playbook adds an investigation checklist; evidence export writes a local report. Desktop notifications are opt-in. Local AI advice cannot change detections or containment states automatically.

Logs, notes and exports may contain personal or sensitive data. Common credential fields/query parameters are redacted, but arbitrary log content is not guaranteed secret-free. Protect the Windows account, files and backups. Events and audit records are not signed or tamper-proof.

This is not a complete Splunk replacement. Distributed forwarders/indexer clusters, high availability, SPL compatibility, enterprise SSO/RBAC, learned UEBA, cloud connectors, vendor-wide detection coverage and remote SOAR containment are not implemented. The no-login desktop design intentionally relies on the local Windows account.

## Reproduce verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\verify_security_monitoring.py
.\.venv\Scripts\python.exe run_desktop.py --self-check .artifacts\verification\desktop.json
```

The monitoring verification script creates clearly labelled synthetic fixtures in a temporary workspace. It checks the real parser/storage/detection/UI pipeline and never adds dummy activity to the production workspace. Native Windows rendering can be inspected by setting `QT_QPA_PLATFORM=windows` for that verification run.

Format references: [Apache logging](https://httpd.apache.org/docs/2.4/logs.html), [Windows event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), [python-evtx](https://github.com/williballenthin/python-evtx).

Workspace backup restore currently limits total uncompressed archive content to 200 MB. Larger datasets need an external backup strategy; deployment-scale retention and storage management have not been validated.
