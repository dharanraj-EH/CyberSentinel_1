# CyberSentinel Desktop

Native desktop software for authorized network, TLS and web configuration assessment, vulnerability intelligence, reporting and remediation tracking.

**The application opens directly to the dashboard. There is no login or registration page.**

## Start

Double-click **Start_CyberSentinel.bat**, use the **CyberSentinel Desktop** VS Code debug configuration, or run:

```powershell
.\.venv\Scripts\python.exe run_desktop.py
```

Fresh installation (Python 3.10 or later):

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The portable build is `dist/CyberSentinel/CyberSentinel.exe`. Keep the entire folder together when distributing it.

## Professional source layout

```text
src/cybersentinel/
  application.py                  Desktop lifecycle
  ui/                             Native desktop interface
    main_window.py
    security_overview.py
    network_assessment.py
    tls_assessment.py
    web_assessment.py
    report_library.py
    vulnerability_intelligence.py
    assessment_workspace.py
    asset_scope.py
    preferences.py
    theme.py
  scanner/                        Assessment engines
    nmap_engine.py
    tcp_scanner.py
    tls_scanner.py
  intelligence/                   NVD vulnerability catalog
  services/                       Assessment storage, scope, model advice
  icons/                          Bundled icons
  utils/                          Resource loading
tests/                            Regression tests
scripts/                          Startup, packaging and evaluation
docs/                             Change log and verification history
run_desktop.py                    Source launcher
Start_CyberSentinel.bat            Windows launcher
pyproject.toml                    Package and dependency configuration
```

Python files use descriptive snake_case names. Standard tool and package filenames retain their conventional names.

## Features and use

The ten desktop modules cover Security Overview, Network Exposure Assessment, TLS & Certificate Assurance, Web Configuration Assessment, Report Library, Vulnerability Intelligence, Asset Inventory & Scope, Assessment Workspace, Local Security Intelligence and Security Monitoring.

**Security Monitoring** imports Apache/Nginx and Windows exports, normalizes/searches events, detects suspicious patterns, groups alerts into incident timelines and links existing scan findings. It also provides watched log files, local indicator matching, configurable rules, incident reports and optional desktop notifications. See [the monitoring guide](docs/SECURITY_MONITORING.md) for formats, rules and operating limits. Private server logs must be provided by an authorized administrator; a public URL does not expose them.

First add authorized assets in **Asset Inventory & Scope**. Loopback is initially allowed. Exclusions take precedence; CIDR scopes are limited to 256 addresses. Run checks, review evidence and confidence, and track remediation in the workspace. JSON, escaped HTML and PDF reports are generated automatically. History comparison, combined target reports and backup/restore are available.

Nmap is optional and must be in PATH for its engine. TCP Connect works without Nmap. NVD queries contact NIST over HTTPS; NVD_API_KEY is optional.

AgentShield's installed qwen3:0.6b model is discovered through local Ollama at http://127.0.0.1:11434. Select a saved assessment in **Local Security Intelligence** to request advisory explanations. Model output cannot execute tools or change findings automatically.

## Local data

The current workspace is `%USERPROFILE%/.cybersentinel/workspaces/local/`. Rotating logs are in `%USERPROFILE%/.cybersentinel/logs/`.

Historical account workspaces and reports in the user profile have not been deleted. Authentication is no longer used. This is a single local workspace protected by the Windows account.

Obsolete code, duplicate launchers, the broken old environment and prior generated files were moved outside the project into `D:/VS Code/CyberSentinel_1_cleanup_backup_20261014` after bulk permanent deletion was blocked by environment policy. The working `.venv` remains.

## Verification and packaging

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe scripts/verify_local_assessments.py
.\.venv\Scripts\python.exe scripts/evaluate_detectors.py
.\.venv\Scripts\python.exe scripts/verify_security_monitoring.py
.\.venv\Scripts\python.exe run_desktop.py --self-check .artifacts/verification/desktop.json
.\scripts\build_desktop.ps1
```

Install development tools with `pip install -e '.[dev]'`. Tests use temporary stores and loopback fixtures. The self-check verifies direct dashboard startup and SQLite/JSON/HTML/PDF operation. See docs for historical verification and changes.

## Limits

Open ports are exposure observations. TLS cipher coverage is sampled. Web probes and CPE matches need analyst validation; failed checks remain inconclusive. The synthetic benchmark does not establish real-world accuracy. Local AI advice may be inaccurate. Local data is not encrypted and the portable application is unsigned. Scheduling, SSO/MFA and deployment-scale evaluation are not implemented.
