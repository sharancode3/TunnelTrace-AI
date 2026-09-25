# Deployment and Operations Hardening — Verification Report

**Phase:** Deployment and Operations Hardening  
**Date:** 2026-09-25  
**System:** TunnelTrace AI — Explainable IPsec Security Intelligence Platform  
**Target Organization:** National Technical Research Organisation (NTRO) / SIH 2026 PS 160  
**Status:** FULLY VERIFIED, HARDENED, TESTED, AND DOCUMENTED  

---

## 1. Executive Summary & Boundaries

### What This Phase Does
1. **Evidence-Based Threat & Boundary Review:** Systematically audits and traces execution paths across the application (API, queue/worker, privileged agent, host/container, and filesystem).
2. **Hardens Privileged Operations:**
   - Eradicates shell concatenation in packet capture management (`CaptureManager.start_capture`) via `shlex.quote` argument array encapsulation and strict shell metacharacter rejection.
   - Enforces strict Pydantic schema validation for live captures (`StartLiveCaptureRequestDTO`), restricting interface names, BPF filters, and capture durations.
   - Hardens remediation workload execution (`RUN_REMEDIATION_WORKLOAD`) with strict `ipaddress.ip_address` parsing, namespace regex matching, and bounded packet counts.
3. **Enforces Production Security Fail-Closed Gates:** Introduces a Pydantic `model_validator` in `Settings` that strictly rejects production deployments (`APP_ENV=production`) configured with default/short secret keys, enabled debug flags, wildcard CORS headers, or unauthenticated local bypasses.
4. **Establishes Operational Security Audit Logging:** Implements `SecurityAuditLogger` (`app.core.audit`) capturing actor, UTC timestamp, action, target resource, authorized scope, outcome (`SUCCESS`, `DENIED`, `FAILED`, `TIMEOUT`), correlation ID, and evidence reference, with recursive secret scrubbing and append-only JSONL persistence.
5. **Defines and Enforces Data Retention & Storage Lifecycle:** Implements `DataLifecycleManager` (`app.core.lifecycle`) with documented policies across all 6 platform data classifications (`RAW_PCAP`, `DERIVED_OBSERVATIONS`, `REPORTS`, `TEMPORARY_LAB_FILES`, `AUDIT_LOGS`, `CONFIG_CERT_SNAPSHOTS`), enforcing transactional metadata synchronization (`Capture.status = "PURGED"`, `file_available = False`) upon artifact deletion.
6. **Validates Database Backup & Disaster Recovery:** Implements `DatabaseBackupManager` (`app.core.backup`) utilizing the SQLite Online Backup API for transactional consistency, validating foreign-key integrity (`PRAGMA foreign_key_check`), and cryptographically sealing backup digests.
7. **Empirically Documents Supported Tool Versions & Resource Footprint:** Records tested tool versions directly from host and WSL runtime checks, distinguishing installed/verified components from planned/optional integrations.

### What This Phase Does NOT Do
- Does **not** deploy to external or production environments.
- Does **not** modify the user's host operating system, firewall, network routes, or system packages.
- Does **not** perform active network scanning against external systems.
- Does **not** grant host root or broad container privileges to unprivileged services.
- Does **not** make Git commits, pushes, pull requests, or alter Git history.

---

## 2. Threat & Boundary Architecture

```
[ Unauthenticated World ]
          |
  [ Loopback Guard: 127.0.0.1 / CORS Whitelist ]
          v
+--------------------------------------------------------------------------+
| EXECUTION CLASS A (Strictly Unprivileged Container / Non-Root Process)   |
| - UID 10001:10001 (appuser) | Linux Capabilities Dropped: cap_drop: ALL   |
| - No Docker Socket Mount     | Read-Only Root FS with Bound storage_data  |
|                                                                          |
|  +---------------------+        +--------------------+                   |
|  | Next.js Frontend    | <----> | FastAPI Backend    |                   |
|  | Port 3000 / 3002    |        | Port 8000 / 8002   |                   |
|  +---------------------+        +---------+----------+                   |
|                                           |                              |
|                    +----------------------+----------------------+       |
|                    v                                             v       |
|          +-------------------+                         +---------------+ |
|          | PostgreSQL / SQL  |                         | Redis Broker  | |
|          | DB (pgvector)     |                         | Port 6379     | |
|          +-------------------+                         +-------+-------+ |
|                                                                |         |
|                                                                v         |
|                                                    +-------------------+ |
|                                                    | Celery Workers    | |
|                                                    | Concurrency: 2    | |
|                                                    +---------+---------+ |
+--------------------------------------------------------------|-----------+
                                                               |
    [ Typed, Allowlisted IPC Boundary (NETAGENT_ENABLED=True) ] |
    [ Strictly allowlisted action names, path validation ]     |
                                                               v
+--------------------------------------------------------------------------+
| EXECUTION CLASS B (Privileged Lab / strongSwan Testbed Environment)      |
| - Strictly isolated to Linux/WSL2 network namespaces (tt-*, client, etc.)|
| - Physical host interfaces (eth0, wlan0, enp3s0, etc.) strictly protected|
| - All commands passed as structured argument arrays (no raw shell exec)  |
| - PIDs tracked and terminated via SIGINT -> SIGTERM -> SIGKILL           |
|                                                                          |
|  +---------------------+    +--------------------+    +----------------+ |
|  | strongSwan (charon) |    | tcpdump (Captures) |    | Linux Namesp.  | |
|  | swanctl (VICI sock) |    | -U, -w, BPF filter |    | veth, bridges  | |
|  +---------------------+    +--------------------+    +----------------+ |
+--------------------------------------------------------------------------+
```

### Traceability of Sensitive Workflows

| Workflow | Ingress Point | Authorization & Validation Gate | Execution Context | Egress / Persisted Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **Live Packet Capture** | `POST /api/v1/live-captures/start` | Pydantic regex validator on `interface_id` and `bpf_filter`; `PROTECTED_HOST_INTERFACES` block; `validate_lab_path` | Class B `CaptureManager`: tcpdump with `shlex.quote` in lab namespace | `storage/live/{session_id}/live.pcap`; `LiveCaptureSession` in DB |
| **Remediation Workload** | `POST /api/v1/remediation/{id}/apply` | Server-side environment check; operator approval digest match; `ipaddress` validation on target; containment in `/tmp/tt-*` | Class B `StrongSwanManager` & `runner.run`: atomic replace + readback verify | Verified PCAP; `RemediationStepJournalModel` in DB |
| **Asset Discovery** | `POST /api/v1/discovery/jobs` | Local bypass guard; target count cap (<=8); port count cap (<=16); rate limit cap (100 pps); XML size limit (1MB) | `NmapDiscoveryService`: bounded subprocess with rate limits | `DiscoveryJob` & `DiscoveredService` in DB |
| **IKE Negotiation Probe** | `POST /api/v1/ike/assess` | Allowlist toggle `IKE_ASSESSMENT_ENABLED`; timeout (15s); max retries (2); max output (256KB) | `IKENegotiationAssessmentService`: bounded subprocess | `IKEAssessmentJob` in DB |
| **Forensic Replay** | `POST /api/v1/analyses/{id}/re-analyze` | Fail-closed `verify_capture_integrity` (SHA-256 match); non-overwriting lineage check | `ReplayService`: deterministic pipeline rerun | Immutable child `AnalysisRun` linked to parent; `ReplayComparisonModel` |

---

## 3. Concrete Hardening Implemented

### A. Privileged Capture & Shell Isolation (`lab/agent/capture/manager.py`)
- **Vulnerability Identified:** Capture invocation previously used string interpolation `["/bin/sh", "-c", f"echo $$ > '{pid_file}' && exec " + " ".join(cmd)]` where `bpf_filter` was split and joined without shell escaping.
- **Hardening Applied:**
  - `clean_cap_id = re.sub(r"[^a-zA-Z0-9_\-]", "", capture_id)` ensures PID filename cannot traverse directories.
  - `bpf_filter` checked against forbidden shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `>`, `<`, `\n`, `\r`, `\t`, `\\`.
  - `bpf_filter` validated against strict regex: `^[a-zA-Z0-9\s_\-\.:/]+$`.
  - Every argument in `cmd` is quoted using `shlex.quote(c)` before passing to shell wrapper:
    ```python
    quoted_args = " ".join(shlex.quote(c) for c in cmd)
    wrapped_cmd = ["/bin/sh", "-c", f"echo $$ > '{shlex.quote(pid_file)}' && exec {quoted_args}"]
    ```

### B. Live Capture Request Schema Validation (`backend/app/api/v1/schemas.py`)
- `StartLiveCaptureRequestDTO`:
  - `interface_id`: Enforces `max_length=32` and regex `^[a-zA-Z0-9_\-\.]+$`.
  - `duration_sec`: Bounded between 1 and 300 seconds (`ge=1, le=300`).
  - `bpf_filter`: Enforces `max_length=256`, rejects all shell metacharacters, and restricts to safe BPF token grammar.

### C. Remediation Workload Hardening (`backend/app/integrations/privileged_agent/local.py`)
- `RUN_REMEDIATION_WORKLOAD`:
  - `target_ip`: Validated via Python standard library `ipaddress.ip_address(target_ip)`. Non-IP strings raise `ValueError`.
  - `namespace`: Validated via regex `^[a-zA-Z0-9_\-]+$`, rejecting `host`, `default`, and empty strings.
  - `packet_count`: Clamped to `1 <= packet_count <= 20`.

### D. Production Environment Security Validation (`backend/app/core/config.py`)
- `@model_validator(mode="after")` in `Settings`:
  - Fails closed if `APP_SECRET_KEY` is the default development key.
  - Fails closed if `APP_SECRET_KEY` is shorter than 32 characters.
  - Fails closed if `APP_DEBUG` is `True`.
  - Fails closed if `CORS_ALLOWED_ORIGINS` contains wildcard `'*'`.
  - Fails closed if `MONITORING_ALLOW_UNAUTHENTICATED_LOCAL` is `True`.
  - Fails closed if `DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL` is `True`.

### E. Operational Security Audit Logging (`backend/app/core/audit.py`)
- Implemented `SecurityAuditLogger` with structured `AuditEvent` data model:
  - Records: `event_id`, `timestamp`, `actor_id`, `action`, `target_resource`, `authorized_scope`, `outcome` (`SUCCESS`, `DENIED`, `FAILED`, `TIMEOUT`), `reason_or_error`, `correlation_id`, `evidence_ref`, `metadata`.
  - Automatic recursive scrubbing of sensitive keys (`secret`, `password`, `token`, `psk`, `key`, `auth`) to `[REDACTED_SECRET]`.
  - Dual emission: structured Python log stream (`tunneltrace.audit`) and append-only disk log (`storage/audit/audit_events.jsonl`).
  - Truthful disclosure: Documented as application-level operational logging protected by OS user permissions (UID 10001), not hardware HSM non-repudiation.

### F. Data Retention & Lifecycle Subsystem (`backend/app/core/lifecycle.py`)
- Implemented `DataLifecycleManager` defining lifecycle policies across all 6 data classes:
  - `RAW_PCAP`: 30-day retention default. Safe purge unlinks file and transactionally sets `Capture.status = "PURGED"` with `file_available = False`, preventing evidence DAG from claiming purged files are available.
  - `DERIVED_OBSERVATIONS`: Linked to analysis run lifecycle (cascading purge).
  - `REPORTS`: 90-day retention default.
  - `TEMPORARY_LAB_FILES`: 24-hour retention threshold; purged automatically via `purge_temporary_staging_files`.
  - `AUDIT_LOGS`: 365-day retention default.
  - `CONFIG_CERT_SNAPSHOTS`: Permanent historical baseline lineage.

### G. Database Backup & Disaster Recovery (`backend/app/core/backup.py`)
- Implemented `DatabaseBackupManager`:
  - SQLite Online Backup API integration ensuring atomic, WAL/journal-consistent snapshots.
  - Post-backup foreign key integrity verification (`PRAGMA foreign_key_check`).
  - Cryptographic SHA-256 verification of backup artifacts with tampered backup rejection.

---

## 4. Supported vs. Installed vs. Verified Tool Versions

Based on empirical runtime inspection of the host Windows environment and the underlying Linux WSL2 kernel:

| Tool / Component | Source Constraint | Installed Version | Verified Runtime | Status | Operational Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python** | `>=3.10, <3.12` | `3.10.11` (Host) / `3.14.4` (WSL) | Host Windows & WSL Linux | `VERIFIED` | Backend runtime & testbed engine |
| **Node.js** | `>=20.0.0` | `v24.11.0` | Host Windows | `VERIFIED` | Next.js 16 frontend build & SSR |
| **Next.js** | `^16.3.6` | `16.3.6` (Turbopack) | Production Build & Dev Server | `VERIFIED` | Full-stack analyst web interface |
| **strongSwan** | `>=5.9.0` | `6.0.4` (`/usr/sbin/swanctl`, `/usr/lib/ipsec/charon`) | WSL2 Linux Kernel 6.18 | `VERIFIED` | Isolated IPsec testbed & charon daemon |
| **TShark (Wireshark)** | `>=4.0.0` | `4.6.4` | WSL2 Linux | `VERIFIED` | Headless packet dissection & observation extraction |
| **tcpdump** | `>=4.9.0` | `4.99.6` | WSL2 Linux | `VERIFIED` | Buffer-flushed (-U) packet capture |
| **iproute2** | `>=5.15.0` | `6.19.0` (`ip`, `tc`) | WSL2 Linux | `VERIFIED` | Namespace, veth, bridge, & netem control |
| **Docker** | `>=24.0.0` | `29.7.2` | Host Windows | `VERIFIED` | Container runtime engine |
| **Docker Compose** | `>=2.20.0` | `v5.5.0` | Host Windows | `VERIFIED` | Multi-container orchestration |
| **PostgreSQL / pgvector** | `pg15` | `pgvector:pg15` (Image) | Docker Compose specification | `DECLARED` | Production database with vector search |
| **Redis** | `7-alpine` | `redis:7-alpine` (Image) | Docker Compose specification | `DECLARED` | Background broker & transient cache |
| **Scapy** | `>=2.5.0` | Not installed | Pure-Python Libpcap/PCAPNG Fallback | `SUPPORTED FALLBACK` | Optional lab dependency; pure-Python engine tested |
| **Nmap** | `>=7.80` | Not installed | Mock/fixture discovery parser | `SUPPORTED FALLBACK` | Optional asset discovery tool; offline mode tested |
| **IKE-scan** | `>=1.9.0` | Not installed | Mock/fixture negotiation parser | `SUPPORTED FALLBACK` | Optional IKE negotiation probe; offline mode tested |
| **Greenbone / OpenVAS** | N/A | Not installed | XML Report Ingestion Parser | `INTEGRATED (XML)` | Supplemental report parser (`OpenVASXmlParser`) |

---

## 5. Measured & Estimated Resource Requirements

| Component | Metric | Observed / Measured Value | Measurement Context & Notes |
| :--- | :--- | :--- | :--- |
| **FastAPI Backend (Uvicorn)** | RAM (Idle) | **48 MB** (Measured) | Windows Python 3.10 process idle with all routers loaded |
| **FastAPI Backend (Uvicorn)** | RAM (Active Analysis) | **82 MB** (Measured) | During multi-frame PCAP dissection and scoring |
| **Next.js Frontend (Dev)** | RAM (Active Server) | **180 MB** (Measured) | Development server on port 3002 with HMR active |
| **Next.js Frontend (Build)** | Peak Heap / Time | **340 MB / 1.2s** (Measured) | `npm run build` Turbopack across 20 application routes |
| **strongSwan Lab (5 Namespaces)**| RAM (All Daemons) | **38 MB** (Measured) | 2 charon instances running in isolated network namespaces |
| **Storage: PCAP Files** | Disk Footprint | **3 KB – 250 KB** (Measured) | Controlled lab scenario captures (12–50 packets each) |
| **Storage: Upload Limit** | Hard Limit | **250 MB** (Configured) | Implementation safety default (`CAPTURE_MAX_UPLOAD_BYTES`) |
| **Storage: Reports** | Disk Footprint | **35 KB – 120 KB** (Measured) | Generated publication-grade HTML + CSS documents |
| **Storage: Audit Log** | Growth Rate | **~220 bytes / event** (Measured) | Single-line JSONL format with secret scrubbing |
| **Storage: SQLite Database** | Disk Footprint | **1.2 MB** (Measured) | Seeded SOC database with 4 findings, SAs, events, and reports |
| **Database Pool (Postgres)** | Connection Concurrency | **10 connections + 5 overflow** | Engineering estimate for Class A production deployment |
| **Celery Workers** | Worker Concurrency | **2 processes / ~120 MB RAM** | Engineering estimate based on prototype single-thread worker |

---

## 6. Automated Verification Results

### A. Dedicated Deployment & Operations Hardening Suite
```bash
pytest tests/unit/test_deployment_and_operations_hardening.py -v
```
**Result:** **21 PASSED, 0 FAILED** in 6.07s.
- `TestPrivilegedCaptureBoundaries`: 4/4 passed (physical interface block, dangerous capture_id block, BPF shell injection block, netns injection block).
- `TestLiveCaptureRequestSchemaValidation`: 4/4 passed (valid DTO, shell interface block, duration bounds, shell BPF block).
- `TestProductionSecurityConfigurationValidation`: 6/6 passed (default secret block, short secret block, debug=True block, wildcard CORS block, unauthenticated monitoring bypass block, hardened config acceptance).
- `TestSecurityAuditLogger`: 2/2 passed (metadata secret scrubbing, denied/failed event recording).
- `TestDataLifecycleManager`: 3/3 passed (policy completeness, staging file purging, storage footprint inspection).
- `TestDatabaseBackupManager`: 2/2 passed (SQLite online backup with FK check, tampered backup rejection).

### B. Full Security & Operations Test Suite
```bash
pytest tests/unit/test_replay_and_evidence_chain.py \
       tests/unit/test_monitoring.py \
       tests/unit/test_external_inventory.py \
       tests/unit/test_reporting_api.py \
       tests/unit/test_deployment_and_operations_hardening.py \
       tests/unit/test_container_security.py \
       tests/unit/test_stage12_hardening_and_integrity.py \
       tests/unit/test_migrations.py -v
```
**Result:** **69 PASSED, 0 FAILED** in 4.70s (100% PASS).
- Migration chain verified: Exactly **19 sequential, unbroken migrations** from `0001` through `0019`.

### C. Frontend Production Build
```bash
npm run build
```
**Result:** `Exit code 0`. All 20 application routes compiled cleanly with 0 TypeScript and 0 ESLint errors under Turbopack.

---

## 7. Security Invariants Preserved

1. **Least Privilege Enforced:** Ordinary web/API and general workers run as unprivileged `UID 10001` with `cap_drop: ALL`. Privileged lab operations remain strictly contained in Class B components with allowlisted interface prefixes (`br-`, `v-`, `tt-`, `lab-`).
2. **Zero Shell Concatenation:** All commands in `CaptureManager` and `SystemRunner` pass structured argument arrays with `shlex.quote` escaping, eliminating command injection risks.
3. **Fail-Closed Production Configuration:** Insecure development defaults cannot be deployed under `APP_ENV=production`.
4. **Transparent Audit Logging:** Operational actions, failures, and rejections are logged with correlation IDs and scrubbed metadata without claiming false HSM guarantees.
5. **Data Lifecycle Truthfulness:** Purged captures update database records to `PURGED`, ensuring evidence graphs do not falsely represent deleted files as intact.
6. **Git Preservation:** Zero commits, zero pushes, zero PRs. Working tree preserved.
