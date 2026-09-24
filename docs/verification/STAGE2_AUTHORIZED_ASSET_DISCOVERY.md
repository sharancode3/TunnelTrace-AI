# Stage 2: Authorized Asset Discovery (Nmap) — Verification Report & As-Built Baseline

**Date of Execution**: 2026-09-24  
**Implementation Stage**: Stage 2 (Authorized Asset Discovery — User-Defined Scope)  
**System Target**: TunnelTrace AI (IPsec VPN Protocol Analysis & Evidence-Driven Assurance)  
**Status**: `VERIFIED & OPERATIONAL (BOUNDED LOCAL TEST MODE)`  
**Repository State**: Working tree modified locally; zero git commits made; zero pushes to remote.

---

## 1. Executive Summary & Verification Matrix

TunnelTrace AI has implemented **Stage 2 — Authorized Asset Discovery with Nmap**, providing a bounded, evidence-driven active discovery subsystem for explicitly approved VPN endpoints and services.

This capability adheres to the core product design principles:
- **Zero Hallucination / Zero Fabrication**: Scanner observations are treated strictly as observational evidence, not vulnerability verdicts or proof of IPsec security.
- **Ambiguity Preservation**: UDP port states such as `open|filtered` remain explicitly recorded as `OPEN_OR_FILTERED` with `has_ambiguity=True`. Absence of an ICMP response is never converted into "open", "closed", "safe", or "vulnerable".
- **Defensive Scope & Execution Bounds**: Subprocess execution requires non-empty operator ID, formal authorization reference, explicit attestation statement, and strict target/port caps. Multicast, broadcast, unspecified addresses, and wildcards are strictly rejected.
- **Subprocess Isolation**: Process invocations use immutable argument arrays with `shell=False`. Process tree cleanup and timeouts (30s) are strictly enforced. Output is parsed with `defusedxml` to block entity expansion and external DTD attacks.
- **Truthful Tool Fallback**: When Nmap is absent from the host, the system truthfully transitions to `TOOL_UNAVAILABLE` without crashing or presenting fallback mock results.

| Verification Item | Requirement | Status | Evidence / Verification Method |
| :--- | :--- | :--- | :--- |
| **Stage 1 Prerequisite Gate** | Real capture trace, worker/DB path, ML inference, and reports | **VERIFIED** | `docs/verification/STAGE1_AS_BUILT_BASELINE.md` present; `test_stage1_as_built_trace.py` passes 100% (11.71s) |
| **Pre-Change Architecture Audit** | Check existing inventory, auth, jobs, worker models | **VERIFIED** | Completed read-only audit. Noted lack of enterprise IdP; established local test mode (`DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL`) |
| **Authorization Gates** | Operator ID, auth reference, explicit attestation statement | **VERIFIED** | Unit tested in `test_discovery_validation.py` (13 tests) |
| **Scope Canonicalization** | IP/CIDR validation, expansion caps, exclusion filtering | **VERIFIED** | Enforces max 8 targets, max 16 ports; excludes targets prior to execution |
| **Hostname Resolution Pinning** | Single-point DNS resolution; pinned IP execution target | **VERIFIED** | Hostnames resolved once before scan; execution pinned to resolved IPs |
| **Subprocess Execution Safety** | `shell=False`, argument array, timeout, process kill, output byte limit | **VERIFIED** | Tested in `test_discovery_runner.py` (6 tests); passed static security regex audit in `test_stage12_hardening_and_integrity.py` |
| **Safe XML Parsing** | `defusedxml`, entity expansion attack defense, byte caps | **VERIFIED** | Tested in `test_discovery_parser.py` (7 tests) including Billion Laughs attack |
| **Ambiguity Preservation** | UDP `open|filtered` mapped to `OPEN_OR_FILTERED` | **VERIFIED** | Canned IKE fixtures verify `has_ambiguity=True` and exact reason tracking |
| **Database & Lineage** | Additive schema `0011`, foreign keys, cascade deletes, async | **VERIFIED** | Migration `0011` created; lineage tested in `test_migrations.py` and `test_stage12_hardening_and_integrity.py` |
| **REST API Contracts** | Endpoints `/api/v1/discovery/...` with typed schemas and 403/422/500 handlers | **VERIFIED** | Tested in `test_discovery_api.py` (6 tests) with isolated database sessions |
| **Frontend UI Workbench** | Dedicated Stage 2 discovery UI with preflight review, status banners, ambiguity callouts | **VERIFIED** | `frontend/src/app/discovery/page.tsx` created; Next.js 16 build passed with 0 errors |
| **Subprocess Absence Handling** | Nmap binary missing -> `TOOL_UNAVAILABLE` | **VERIFIED** | Tested via mock and real host inspection (`where.exe nmap` = not found) |

---

## 2. Stage 1 Prerequisite Gate: As-Built Baseline Verification

Before implementing Stage 2, the Stage 1 prerequisite state was verified:
- **Baseline Report**: Located and verified at [`docs/verification/STAGE1_AS_BUILT_BASELINE.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/verification/STAGE1_AS_BUILT_BASELINE.md).
- **Integration Test**: Located and executed [`backend/tests/integration/test_stage1_as_built_trace.py`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/backend/tests/integration/test_stage1_as_built_trace.py).
  - Executed against canonical capture fixture `tests/fixtures/captures/real_tunnel_gcm.pcapng` (SHA-256: `949531329196d1fbc836ee0685efe8a204c68d6d8da5a5b75ecaa0128c59e04d`).
  - Result: **1 passed in 11.71s** (full lifecycle including TShark dissection, flow reconstruction, XGBoost/CNN inference, deterministic policy evaluation, manifest generation, and technical report snapshot generation).
- **Prerequisite Verdict**: **PASSED (UNBLOCKED)**.

---

## 3. Pre-Implementation Architecture Audit

A read-only architecture audit of the repository was conducted before modifications:
1. **Authentication & Authorization**:
   - The backend currently lacks an active OAuth2/OIDC or database-backed user authentication system (workspaces/tenants are currently managed at the process/session level).
   - *Design Decision*: We make this limitation explicit. Active discovery is gated by local operator controls and authorization fields (`operator_id`, `authorization_reference`, `authorization_attestation`). In settings, `DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL = True` permits standalone lab testing. In production deployments, this flag must be toggled off to require upstream IdP headers.
2. **Scanner & Worker Infrastructure**:
   - The existing workers (`app.workers.protocol_tasks`, `app.workers.health_tasks`) focus on capture dissection and strongSwan testbed management.
   - *Design Decision*: Bounded Nmap discovery runs through a dedicated, asynchronous discovery service (`app.discovery.service.DiscoveryService`) running subprocess operations in a thread executor (`asyncio.to_thread`) to prevent blocking the event loop.
3. **Database & ORM**:
   - SQLAlchemy 2.0 with asynchronous PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`) support.
   - *Design Decision*: Created `backend/app/db/models/discovery.py` defining `DiscoveryJob`, `DiscoveredHost`, and `DiscoveredService` with JSONB/JSON column mappings, UUID primary keys, and relationship cascades.

---

## 4. Authorization & Scope Security Model

Active discovery scans require affirmative operator inputs before any subprocess can be constructed:
1. **Operator Principal (`operator_id`)**: Non-empty string identifying the requesting technician.
2. **Authorization Reference (`authorization_reference`)**: Non-empty ticket number, change order code, or engagement identifier (e.g. `CHG-2026-0924`).
3. **Attestation Statement (`authorization_attestation`)**: Explicit text statement of at least 10 characters confirming the scope has been authorized.
4. **Target Validation & Scope Hardening**:
   - Rejects empty target lists.
   - Rejects wildcard/broad targets (`*`, `all`, `0.0.0.0/0`, `::/0`).
   - Rejects multicast (`224.0.0.0/4`), unspecified (`0.0.0.0`, `::`), and reserved address spaces.
   - Hostnames are syntax-validated against RFC 1123, resolved exactly once at pre-flight time, and execution is strictly pinned to the resolved IPs.
   - Exclusions are applied to all candidate IPs prior to execution. If zero targets remain, the request is rejected immediately.
   - Requests failing authorization return `HTTP 403 Forbidden`; requests failing scope validation return `HTTP 422 Unprocessable Entity`.

---

## 5. Fixed Allowlisted Profiles & Numerical Hard Limits

Arbitrary Nmap arguments, script execution (`--script`), OS fingerprinting (`-O`), aggressive timing (`-T4`, `-T5`), and raw SYN scans (`-sS` without privilege) are forbidden.

### Fixed Profiles (`app.discovery.profiles.DiscoveryProfile`)
| Profile Identifier | Description | Protocol | Default Ports | Timing & Rate Controls | Base Arguments |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `IKE_SERVICE_DISCOVERY` | Bounded UDP discovery for IKE and IPsec NAT-Traversal | UDP | `[500, 4500]` | `-T3`, `--max-rate 100` | `["-sU", "-Pn", "-n"]` |
| `VPN_MANAGEMENT_DISCOVERY` | Unprivileged TCP connect discovery for authorized VPN portals | TCP | `[22, 80, 443, 8443]` | `-T3`, `--max-rate 100` | `["-sT", "-Pn", "-n"]` |
| `CUSTOM_BOUNDED` | Strictly bounded custom port discovery within configured caps | UDP/TCP | Operator specified (capped at 16) | `-T3`, `--max-rate 100` | `["-Pn", "-n"]` |

### Hard Limit Safeguards (`app.core.config.Settings`)
- `DISCOVERY_MAX_TARGETS`: **8 IP addresses** (conservative cap preventing network sweeps).
- `DISCOVERY_MAX_PORTS`: **16 ports** (conservative cap preventing broad service sweeps).
- `DISCOVERY_TIMEOUT_SEC`: **30.0 seconds** (hard process timeout; terminates process tree on expiration).
- `DISCOVERY_MAX_OUTPUT_BYTES`: **1,048,576 bytes (1 MB)** (prevents memory exhaustion from oversized XML).
- `DISCOVERY_RATE_LIMIT_PPS`: **100 packets/sec** (prevents network saturation and IDS/IPS disruption).

---

## 6. Process Isolation & XML Parsing Safeguards

### Subprocess Invocation (`app.discovery.runner.run_discovery_scan`)
- `shell=False`: Never invokes a system shell. Arguments are passed as an immutable list of strings.
- Target array passed directly without string concatenation or shell variable expansion.
- Execution happens within a dedicated temporary directory (`tunneltrace_nmap_<job_id>_*`).
- On timeout, process tree termination is executed (`taskkill /F /T` on Windows, `proc.kill()` on POSIX).
- Stderr diagnostics are sanitized with regex to redact absolute paths and credentials before persistence or logging.
- SHA-256 cryptographic digest is calculated over the raw XML output bytes and stored in `DiscoveryJob.raw_output_sha256`.

### Safe XML Parsing (`app.discovery.parser.parse_nmap_xml`)
- Built with `defusedxml.ElementTree` to prevent Billion Laughs entity expansion attacks and external DTD retrieval.
- Validates expected root tag `<nmaprun>` and `scanner="nmap"`.
- Extracts host state (`UP`, `DOWN`, `UNKNOWN`), IP addresses, hostnames, and ports.
- Maps `open|filtered` to `OPEN_OR_FILTERED` and flags `has_ambiguity = True`.
- Extracts service banner metadata (product, version, confidence, reason) as observational facts without converting them into vulnerability verdicts or CVE assertions.

---

## 7. Database Persistence & Migration Lineage

- **Table `discovery_jobs`**: Stores audit fields, operator ID, authorization reference/attestation, canonical targets JSONB, exclusions JSONB, permitted ports JSONB, status, raw output SHA-256, tool version, and timestamps.
- **Table `discovered_hosts`**: Stores individual host IP addresses, IP version, status, hostnames, and foreign key to `discovery_jobs`.
- **Table `discovered_services`**: Stores port, protocol, state (`OPEN`, `CLOSED`, `FILTERED`, `OPEN_OR_FILTERED`), state reason, service banner, product, version, confidence, and foreign key to `discovered_hosts` and `discovery_jobs`.
- **Alembic Migration**: `backend/alembic/versions/0011_stage2_authorized_discovery.py` revises `0010`. Lineage verified:
  ```
  0011 -> 0010 -> 0009 -> 0008 -> 0007 -> 0006 -> 0005 -> 0004 -> 0003 -> 0002 -> 0001 -> None
  ```

---

## 8. Test Execution Evidence

### 1. Discovery Subsystem Tests (33 Passed in 8.24s)
```bash
pytest backend/tests/unit/test_discovery_validation.py \
       backend/tests/unit/test_discovery_parser.py \
       backend/tests/unit/test_discovery_runner.py \
       backend/tests/integration/test_discovery_api.py \
       backend/tests/unit/test_migrations.py
```
- `test_discovery_validation.py`: 13 passed (missing auth, trivial attestation, wildcard prohibited, multicast/unspecified prohibited, CIDR cap exceeded, IP cap exceeded, port cap exceeded, exclusions filtering, DNS pinning).
- `test_discovery_parser.py`: 7 passed (empty XML, oversized XML, invalid root, Billion Laughs entity expansion attack defense, UDP IKE ambiguity preservation, TCP service extraction, multi-host tracking).
- `test_discovery_runner.py`: 6 passed (safe argv construction, tool missing detection, timeout cancellation, process kill, stderr path sanitization).
- `test_discovery_api.py`: 6 passed (status endpoint, unauthorized 403, multicast 422, tool unavailable state persistence, success with ambiguity persistence, cancel endpoint).
- `test_migrations.py`: 1 passed (Alembic linear history 0011 -> 0001).

### 2. Full Backend Unit Test Suite (322 Passed in 24.35s)
```bash
pytest backend/tests/unit/
====================== 322 passed, 19 warnings in 24.35s ======================
```

### 3. Stage 1 As-Built Integration Trace (1 Passed in 11.71s)
```bash
pytest backend/tests/integration/test_stage1_as_built_trace.py
======================= 1 passed, 4 warnings in 11.71s ========================
```

### 4. Frontend Production Build Verification (Zero Errors)
```bash
npm run build
✓ Compiled successfully in 4.4s
  Finished TypeScript in 3.2s
  Collecting page data using 11 workers ...
✓ Generating static pages using 11 workers (7/7) in 268ms
Route (app)
├ ○ /discovery (prerendered static content)
```

---

## 9. Modified and Created Files

### Backend Files Created
1. `backend/app/db/models/discovery.py` — SQLAlchemy models for `DiscoveryJob`, `DiscoveredHost`, `DiscoveredService`.
2. `backend/alembic/versions/0011_stage2_authorized_discovery.py` — Database migration for Stage 2 discovery tables.
3. `backend/app/discovery/__init__.py` — Package exports.
4. `backend/app/discovery/profiles.py` — Allowlisted scan profiles and timing configurations.
5. `backend/app/discovery/validator.py` — Target canonicalization, DNS resolution pinning, and scope validation.
6. `backend/app/discovery/parser.py` — Safe Nmap XML parser with `defusedxml` and ambiguity preservation.
7. `backend/app/discovery/runner.py` — Safe subprocess runner with process bounds and path sanitization.
8. `backend/app/discovery/service.py` — Asynchronous discovery service orchestrator.
9. `backend/app/api/v1/discovery/__init__.py` — Discovery API package export.
10. `backend/app/api/v1/discovery/schemas.py` — Pydantic V2 DTOs with `ConfigDict`.
11. `backend/app/api/v1/discovery/router.py` — FastAPI discovery endpoints with status, job creation, and inspection.
12. `backend/tests/unit/test_discovery_validation.py` — 13 unit tests for validation and authorization gates.
13. `backend/tests/unit/test_discovery_parser.py` — 7 unit tests for XML parsing and Billion Laughs defense.
14. `backend/tests/unit/test_discovery_runner.py` — 6 unit tests for runner bounds and argv security.
15. `backend/tests/integration/test_discovery_api.py` — 6 integration tests with isolated database sessions.

### Backend Files Modified
1. `backend/app/core/config.py` — Added discovery settings (`DISCOVERY_ENABLED`, `DISCOVERY_MAX_TARGETS`, `DISCOVERY_MAX_PORTS`, `DISCOVERY_TIMEOUT_SEC`, `DISCOVERY_RATE_LIMIT_PPS`, `DISCOVERY_MAX_OUTPUT_BYTES`, `NMAP_PATH`, module alias `settings`).
2. `backend/app/db/models/__init__.py` — Registered discovery models.
3. `backend/app/api/v1/router.py` — Mounted discovery router under `/api/v1/discovery`.
4. `backend/tests/unit/test_migrations.py` — Updated migration chain to assert head `0011`.
5. `backend/tests/unit/test_stage12_hardening_and_integrity.py` — Updated sequential migration count to 11.

### Frontend Files Created & Modified
1. `frontend/src/app/discovery/page.tsx` — Created dedicated Stage 2 Asset Discovery UI workbench.
2. `frontend/src/lib/api/types.ts` — Added `DiscoveryJobDTO`, `DiscoveredHostDTO`, `DiscoveredServiceDTO`, `DiscoveryStatusDTO`, and `DiscoveryJobCreateRequestDTO`.
3. `frontend/src/lib/api/client.ts` — Added discovery client methods (`getStatus`, `listJobs`, `getJob`, `createJob`, `cancelJob`).
4. `frontend/src/components/layout/sidebar.tsx` — Added "Asset Discovery (STAGE 2)" link under OVERVIEW group.

---

## 10. Operational Limitations & Known Environmental Gaps

1. **Host Nmap Executable Availability**:
   - On this development host, Nmap is not currently installed (`where.exe nmap` returned not found).
   - In accordance with the prompt's instructions, the system truthfully transitions jobs to `status: "TOOL_UNAVAILABLE"` and displays honest diagnostic messages in both the API and UI without crashing or faking scan observations.
2. **Authentication Framework**:
   - Enterprise identity federation (e.g. Keycloak/OAuth2) is not yet implemented in the core repository.
   - Active discovery operates in local authorized test mode (`DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL = True`). All jobs permanently log the operator-supplied identifier, authorization ticket, and attestation text to maintain an audit trail.
3. **UDP Packet Behavior**:
   - In standard network environments without elevated raw socket privileges, UDP service responses are subject to OS filtering. Probes that receive no response are recorded as `OPEN_OR_FILTERED` to avoid false assertions of service openness.

---

## 11. Handoff & Maintenance Invariants

- **Git State**: No commits or branch changes were made. All edits remain local in the working tree.
- **Test Integrity**: All 322 unit tests, 6 discovery integration tests, and the Stage 1 as-built trace test pass cleanly.
- **Frontend State**: Next.js production build passes with zero TypeScript or compilation errors.
