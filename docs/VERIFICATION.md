# Verification record â€” 13 October 2026

Environment: Windows 11, Python 3.14.6, PyQt5 5.15.11, Nmap 7.98 and the existing AgentShield Ollama qwen3:0.6b model. Exact Python packages are recorded in requirements-lock.txt.

| Check | Result |
| --- | --- |
| Regression suite | 28 tests passed |
| Dependency resolution | pip check: no broken requirements |
| Source compilation | Passed |
| Real loopback TCP scan | Open fixture port detected |
| Real loopback Nmap scan | Structured XML parsed successfully |
| Real loopback HTTP checks | Missing configuration observed |
| Real loopback TLS 1.2 / TLS 1.3 | Self-signed fixture inspected and protocol negotiation exercised |
| NVD API 2.0 | Live CVE-2021-44228 record retrieved with score 10.0 |
| AgentShield model discovery | Installed qwen3:0.6b discovered |
| Local model advisory | Real response generated; advice remains untrusted and separate from evidence |
| Desktop smoke verification | Nine modules, Argon2, SQLite and JSON/HTML/PDF initialized successfully |
| Portable Windows build | Executable built and smoke verified |
| Synthetic detector benchmark | 4 expected flags, 4 expected non-flags, 0 false flags, 0 missed flags, 0 errors |

The benchmark's precision and recall are 1.0 on only these eight constructed fixtures. This is not evidence of general vulnerability-detection accuracy. No external target was scanned during verification. Live external requests were limited to package/documentation retrieval and NVD intelligence; model inference used the existing local service.

Generated diagnostic JSON and screenshots are in verification-output (ignored by Git). Run the documented commands to reproduce them. No independent security review, production load evaluation or installer signing has been performed.

14 October authentication update: sign-in and registration visually checked at 100% and 150% scaling. Real temporary-account registration and failed/successful sign-in passed. Startup rejection exits cleanly; successful startup creates the main window.

Current verification after login removal and source cleanup: 25 tests pass, including a fresh-process test that verifies the dashboard appears with no authentication dialogs. Historical authentication test results above describe the prior version.


## Version 0.3 monitoring verification — 14 October 2026

52 regression tests pass, including UTC/format normalization, unsafe XML rejection, malformed-record reporting, stable imports, overlapping Windows record identities, threshold/time/asset boundaries, success-after-failure correlation, request rates, encoded request patterns, full-text/structured/time search, local indicator matching/import errors, analyst workflow, reopening after later evidence, incident reports, backup/restore, live partial-line/checkpoint/truncation behavior, and BOM/CRLF import/watch consistency.

The desktop verification uses six synthetic events in a temporary workspace and checks two evidence-backed alerts, one incident, a complete timeline, links to a synthetic scan, triage workflow and JSON/HTML/PDF reports. Native Windows-rendered screenshots were inspected. No synthetic security activity is added to the actual workspace. The EVTX integration is installed; native binary EVTX coverage has not been benchmarked against a broad export corpus. Large-scale throughput and independent detection accuracy remain unverified.
