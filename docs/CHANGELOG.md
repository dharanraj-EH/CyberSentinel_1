# Desktop enhancement verification

Implemented on 13 October 2026:

- Consolidated authenticated entry points, root packaging configuration and VS Code debug configuration.
- Nine native desktop modules, sidebar navigation, shared theme, real dashboard data and persisted preferences.
- Argon2id password storage, legacy hash migration and process-local login throttling.
- Per-account authorized asset inventory, exclusions and bounded network scopes.
- Cooperative worker cancellation, subprocess termination, scan deadlines and nonzero-exit handling.
- Same-origin bounded web transport; failed checks remain inconclusive; optional query-only SQL/error and inert HTML reflection checks.
- Exact TLS version negotiation, unknown states for untestable protocols, sampled-cipher disclosure and removal of unsupported Heartbleed inference.
- NVD 2.0 product lookup, pagination, local cache and conservative candidate matching.
- Normalized findings, redacted raw evidence, per-account history, comparison and remediation states with reasons.
- Matching JSON/HTML/PDF reports, combined target reports, consistent backups and validated restore.
- Working AgentShield Ollama model discovery and local advisory generation using installed qwen3:0.6b.
- Regression tests and real loopback transport verification.

Verification includes real local TCP, Nmap, HTTP and self-signed TLS fixtures; a live NVD CVE-2021-44228 lookup; a real local qwen3:0.6b advisory; and desktop initialization/report smoke checks. Production detection accuracy, deployment-scale load, independent penetration testing and Windows installer signing have not been established.

The legacy application tree is retained for reference, not used as a second supported implementation. Remaining enterprise capabilities and limitations are documented in README.md.

Authentication UI update — 14 October 2026: replaced clipped fixed-size dialogs with responsive scrollable forms, consistent high-contrast styling, visible labelled fields, password visibility control and one registration path. Registration/sign-in integration tests added; startup cancellation and successful transition checked.

14 October 2026 — Desktop consolidation: removed login/registration, adopted the local workspace and src/cybersentinel layout, descriptive snake_case modules and one Windows launcher. Obsolete files were archived outside the project after bulk permanent deletion was blocked.


## 0.3.0 — 14 October 2026

Added native Security Monitoring with Apache/Nginx and Windows XML/JSON/CSV/EVTX imports, RFC 5424 syslog support, normalized UTC events, SQLite full-text search, exact filters and paging. Added configurable failed-login, request-rate, suspicious-URL, success-after-failures and local indicator detections. Alerts retain triggering events and original rule snapshots; incidents include risk weights, timeline, owner/state/reason, audit, asset aliases and scan findings.

Added incremental watched-file collection with persistent checkpoints, partial-line handling and rotation/truncation detection; opt-in desktop alert notifications; local IP/domain indicator imports; monitoring charts; incident JSON/HTML/PDF reports; internal triage/evidence workflows; existing local model advice for incidents; and a read-only Windows XML export helper. No login page was reintroduced.

Verification: 52 regression tests, isolated desktop import/detection/investigation verification, and source/portable smoke checks. Synthetic fixtures are used only in temporary verification workspaces. See SECURITY_MONITORING.md for coverage, limits and remaining enterprise capabilities.
