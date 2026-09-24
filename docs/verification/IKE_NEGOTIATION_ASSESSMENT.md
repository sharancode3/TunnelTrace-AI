# Verification Report: Stage 3 — IKE/IPsec Negotiation Assessment

**Document ID:** `TT-VERIFY-STAGE3-IKE-ASSESSMENT-001`  
**Date:** September 24, 2026  
**Status:** **PARTIALLY VERIFIED (Offline Dissection & Mocked Subprocess Verified; Live Scanner Probing Blocked by Tool Availability)**  
**Author:** Antigravity Implementation Agent  

---

## 1. Executive Summary & Prerequisite Verdicts

This report documents the implementation and verification of the user-defined phase **"IKE/IPsec Negotiation Assessment"** (Stage 3 in the user-defined audit sequence), following Stage 1 as-built baseline audit and Stage 2 authorized Nmap asset discovery.

### 1.1 Prerequisite Audit Findings

| Prerequisite Stage | Artifacts Verified | Verdict | Details |
| :--- | :--- | :--- | :--- |
| **Stage 1: As-Built Baseline Audit** | `docs/verification/STAGE1_AS_BUILT_BASELINE.md`<br>`backend/tests/integration/test_stage1_as_built_trace.py` | **VERIFIED (In-Process)** | Isolated real-capture PCAP trace passed 100% (23/23 proof obligations). Browser end-to-end testing was blocked; Celery ran in-process. |
| **Stage 2: Authorized Nmap Discovery** | `docs/verification/STAGE2_AUTHORIZED_ASSET_DISCOVERY.md`<br>`backend/alembic/versions/0011_stage2_authorized_discovery.py`<br>`backend/tests/unit/test_discovery_*.py`<br>`backend/tests/integration/test_discovery_api.py` | **VERIFIED** | 33 unit and integration tests passing; Alembic migration 0011 verified; scope validation, bounded Nmap runner, and XML parser operational. |

---

## 2. Toolchain Inventory & Environmental Limits

As required by the strict truthfulness mandate, the active execution environment was inspected before designing and executing tests:

| Tool | Resolved Path | Version / Build | Status in Environment | Operational Handling |
| :--- | :--- | :--- | :--- | :--- |
| **TShark** | `/usr/bin/tshark` (via WSL2 bridge) | `TShark (Wireshark) 4.6.4` on `Linux 6.18.33.2-microsoft-standard-WSL2` | **OPERABLE** | Canonical machine dissector for passive PCAP extraction, IKE exchange reconstruction, and transform identification. |
| **IKE-scan** | `N/A` | `command not found` (Checked native Windows PATH and WSL2 `/usr/bin/ike-scan`) | **TOOL_UNAVAILABLE** | Truthfully reported as unavailable. Active network probing is disabled by default; mocked unit and canned fixture tests verify the entire parser, runner, and API pipeline. |
| **Wireshark** | Desktop GUI / CLI | Reference dissector matching TShark 4.6.4 | **REVIEW TOOL** | Analyst review and cross-check; not an independent competing machine parser. Original PCAPs remain immutable and read-only. |

---

## 3. Scope & Authorization Policy

The IKE assessment module reuses the authorization principles from Stage 2 while enforcing strict single-target constraints:

1. **Master Toggle:** `settings.IKE_ASSESSMENT_ENABLED` controls overall availability.
2. **Explicit Operator Attestation:** Requests require non-empty `operator_id`, `authorization_reference`, and an explicit attestation statement of at least 10 characters confirming authorized testing scope.
3. **Strict Single Discrete Target:** Multi-target lists and CIDR range sweeps (e.g. `/24`) are strictly rejected with `ScopeValidationError`.
4. **Address Boundary Guards:** Multicast (`224.0.0.0/4`), broadcast (`255.255.255.255`), and unspecified (`0.0.0.0`, `::`) addresses are rejected prior to any subprocess launch. Hostnames are resolved and pinned at validation time.
5. **Port Allowlisting:** Default port is 500, with allowlisted 4500 (NAT-T) and bounded UDP port ranges (1–65535).

---

## 4. Allowlisted Scan Profiles & Forbidden Option Guards

### 4.1 Allowlisted Profiles

| Profile Name | Requested IKE Version | Retries | Timeout | Experimental | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `IKEV1_MAIN_MODE_DISCOVERY` | 1 | 2 | 2000 ms | No | Bounded IKEv1 Main Mode handshake and vendor ID probe. |
| `IKEV2_DEFAULT_EXPERIMENTAL` | 2 | 2 | 2000 ms | **YES** | Probes IKEv2 default proposal via `ike-scan -2`. Explicitly marked experimental; does not enumerate full transform sets. |

### 4.2 Prohibited Features & Safety Guards

The following features and arguments are forbidden from execution:
- `--pskcrack`, `-P`: Zero credential harvesting, offline cracking, or authentication material capture.
- `-A`, `--aggressive`: Aggressive Mode identity enumeration is excluded.
- `--fuzz`, `--random`: Malformed packet injection and fuzzing are excluded.
- `--sport`, `--source-ip`: Spoofing and evasion techniques are excluded.
- Custom transform sweeps / user-defined strings: Arbitrary `--trans` injections are rejected.

Enforced by `app.protocol.ike_scan.profiles.assert_no_forbidden_arguments(argv)` before subprocess invocation.

---

## 5. Epistemic Architecture & Evidence Concordance

Directly observable protocol facts are separated into distinct lanes to prevent halluncinated conclusions:

```
+-----------------------------------------------------------------------------------+
|                           EVIDENCE CONCORDANCE ENGINE                             |
+------------------------------------+----------------------------------------------+
| Lane 1: Passive Observation (TShark) | Lane 2: Active Scanner Probe (IKE-scan)     |
| - Ground Truth from PCAP frames      | - Observational probe response only        |
| - Offered / Selected Transforms      | - Accepted transforms / Notify codes       |
| - Frame references & capture hash    | - Target IP, RTT ms, tool version          |
| - Encrypted IKE_AUTH marked protected| - IKEv2 marked experimental (default only) |
+------------------------------------+----------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
| Concordance Status: CONSISTENT | CONFLICT | INSUFFICIENT_EVIDENCE | NOT_COMPARABLE|
+-----------------------------------------------------------------------------------+
```

### 5.1 Epistemic Rules
- **Active Probe Evidence $\neq$ Tunnel Security:** An IKE-scan handshake response indicates only that an endpoint responded to a probe. It does not prove authentication succeeded, an SA was established, or that the tunnel is operational.
- **IKEv2 Experimental Limits:** Upstream `ike-scan` documentation states IKEv2 is experimental and limited to default proposals. TunnelTrace AI labels IKEv2 probe results as experimental and relies on passive TShark `IKE_SA_INIT` dissection for comprehensive negotiation facts.
- **Encrypted Payloads:** Passive dissection marks subsequent `IKE_AUTH` payloads as encrypted; no passive visibility of protected credentials or certificates is claimed.
- **Unknowns Remain Unknown:** Mid-stream captures lacking initial negotiations are classified as `NOT_OBSERVED` / `INSUFFICIENT_EVIDENCE`.

---

## 6. Implementation Architecture

### 6.1 Database Models & Migration 0012
Created in `backend/app/db/models/ike_assessment.py` and persisted via `backend/alembic/versions/0012_stage3_ike_assessment.py`:
1. `ike_assessment_jobs`: Audited job records with operator ID, authorization attestation, target IP/port, profile, status, tool version, and raw stdout SHA-256 digest.
2. `ike_probe_results`: Normalized probe observations (category `RESPONDED_HANDSHAKE`, `RESPONDED_NOTIFY`, `NO_RESPONSE`, `TOOL_UNAVAILABLE`), IKE version, transforms returned, notify code/message, vendor IDs, RTT, and `is_experimental` flag.
3. `ike_concordance_records`: Triangulated concordance linking passive analysis runs with active probe results (`CONSISTENT`, `CONFLICT`, `INSUFFICIENT_EVIDENCE`, `NOT_COMPARABLE`).

### 6.2 Backend Services & APIs
Created under `backend/app/protocol/ike_scan/` and `backend/app/api/v1/protocol/`:
- `profiles.py`: Finite allowlisted profiles and forbidden flag validation.
- `validator.py`: Scope validation, IP resolution, and attestation checks.
- `parser.py`: Deterministic stdout parser distinguishing handshakes, notifies, silence, and vendor IDs.
- `runner.py`: Subprocess runner with `shell=False`, argument vectors, timeouts, and WSL2 toolchain resolution.
- `concordance.py`: Concordance evaluation engine comparing passive TShark SAs and active IKE-scan results.
- `service.py`: Orchestrator managing job lifecycle, DB persistence, and concordance evaluation.
- `ike_router.py`: FastAPI endpoints mounted under `/api/v1/ike-assessment`:
  - `GET /status`: Tool availability and operational limits.
  - `POST /jobs`: Authorized job creation and execution.
  - `GET /jobs`: Audit job list.
  - `GET /jobs/{id}`: Detailed job and normalized probe results.
  - `GET /analyses/{id}/concordance`: Concordance evaluation for analysis runs.

### 6.3 Frontend Evidence Concordance View
Updated `frontend/src/app/analyses/[analysisId]/protocol/page.tsx`, `client.ts`, and `types.ts`:
- Added 3-lane Evidence Concordance view (Passive TShark Lane, Active IKE-scan Lane, Lab Ground Truth Lane).
- Displaying toolchain availability status truthfully (`OPERABLE` vs `UNAVAILABLE ON HOST`).
- Displaying concordance verdict badge (`CONSISTENT`, `CONFLICT`, `INSUFFICIENT_EVIDENCE`, `NOT_COMPARABLE`).
- Prominent epistemic guardrails and experimental IKEv2 limitation notices.

---

## 7. Verification Evidence & Test Execution

### 7.1 Test Execution Matrix

| Test Suite | File | Count | Exit Code | Result | Details |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **IKE Profiles** | `backend/tests/unit/test_ike_scan_profiles.py` | 3 | 0 | **PASSED** | Finite profiles, forbidden flags (`--pskcrack`, `-A`, `-P`), standard args. |
| **IKE Validator** | `backend/tests/unit/test_ike_scan_validator.py` | 4 | 0 | **PASSED** | Authorization metadata, single IP enforcement, CIDR/multicast/broadcast rejection. |
| **IKE Parser** | `backend/tests/unit/test_ike_scan_parser.py` | 5 | 0 | **PASSED** | Canned fixtures: IKEv1 handshake, notify code 14, no response, IKEv2 experimental, error. |
| **IKE Runner** | `backend/tests/unit/test_ike_scan_runner.py` | 5 | 0 | **PASSED** | Mocked subprocess, safe argv, shell=False, timeout, tool-unavailable fallback. |
| **Concordance** | `backend/tests/unit/test_ike_concordance.py` | 5 | 0 | **PASSED** | Multi-source concordance: consistent, conflict, missing passive, no active response. |
| **IKE API & DB** | `backend/tests/integration/test_ike_assessment_api.py` | 6 | 0 | **PASSED** | Isolated async SQLite DB; 403 authorization guard; 422 CIDR rejection; tool-unavailable state; completed job persistence; concordance endpoint. |
| **Migrations** | `backend/tests/unit/test_migrations.py` | 1 | 0 | **PASSED** | Linear 0001 -> 0012 migration lineage without branches or detached heads. |
| **Hardening** | `backend/tests/unit/test_stage12_hardening_and_integrity.py` | 4 | 0 | **PASSED** | Subprocess audit, secrets audit, linear migrations, air-gapped configuration safety. |
| **Discovery Regr.** | `backend/tests/unit/test_discovery_*.py`<br>`backend/tests/integration/test_discovery_api.py` | 32 | 0 | **PASSED** | All Stage 2 Discovery tests pass with zero regression. |
| **Frontend Types** | `frontend/` (`npx tsc --noEmit`) | N/A | 0 | **PASSED** | Zero TypeScript compilation or type errors. |

**Total Tests Passed:** 65 passing backend tests (28 IKE Assessment + 37 Discovery/Hardening/Migration) + 1 frontend type validation pass.

---

## 8. Blockers & Limitations

1. **Host Scanner Absence:** `ike-scan` is not installed on the Windows host or in the WSL2 environment. In accordance with user requirements, the system does not simulate or fake live execution; it reports `TOOL_UNAVAILABLE` truthfully and keeps live active scanning disabled while passive packet dissection remains operational.
2. **IKEv2 Upstream Limitation:** As documented upstream, `ike-scan -2` is experimental and limited to default proposals. Detailed IKEv2 transform negotiation must be verified through passive TShark packet captures of the `IKE_SA_INIT` exchange or controlled strongSwan testbed testing.
3. **No External Network Scanning:** In compliance with safety guardrails, no live external IP scans were conducted during development or verification.

---

## 9. Modified & Untracked Files Inventory

### 9.1 New Files Created
- `backend/alembic/versions/0012_stage3_ike_assessment.py`
- `backend/app/db/models/ike_assessment.py`
- `backend/app/protocol/ike_scan/__init__.py`
- `backend/app/protocol/ike_scan/profiles.py`
- `backend/app/protocol/ike_scan/validator.py`
- `backend/app/protocol/ike_scan/parser.py`
- `backend/app/protocol/ike_scan/runner.py`
- `backend/app/protocol/ike_scan/concordance.py`
- `backend/app/protocol/ike_scan/service.py`
- `backend/app/api/v1/protocol/ike_schemas.py`
- `backend/app/api/v1/protocol/ike_router.py`
- `backend/tests/unit/test_ike_scan_profiles.py`
- `backend/tests/unit/test_ike_scan_validator.py`
- `backend/tests/unit/test_ike_scan_parser.py`
- `backend/tests/unit/test_ike_scan_runner.py`
- `backend/tests/unit/test_ike_concordance.py`
- `backend/tests/integration/test_ike_assessment_api.py`
- `docs/verification/IKE_NEGOTIATION_ASSESSMENT.md` (this report)

### 9.2 Modified Files
- `backend/app/core/config.py` (added IKE assessment settings)
- `backend/app/db/models/__init__.py` (registered IKE assessment models)
- `backend/app/api/v1/router.py` (mounted `/ike-assessment` router)
- `backend/tests/unit/test_migrations.py` (updated for 0012 migration head)
- `backend/tests/unit/test_stage12_hardening_and_integrity.py` (updated for 12 migrations)
- `frontend/src/lib/api/types.ts` (added IKE assessment DTOs)
- `frontend/src/lib/api/client.ts` (added `ikeAssessment` API client)
- `frontend/src/app/analyses/[analysisId]/protocol/page.tsx` (added Evidence Concordance 3-lane view)

---

## 10. Next-Phase Handoff

The IKE/IPsec Negotiation Assessment foundation is complete, verified, and integrated into the product architecture:
- TShark 4.6.4 remains the canonical machine dissector for passive PCAP evidence.
- IKE-scan adapter is strictly bounded, auditable, non-intrusive, and disabled when the toolchain is absent.
- Multi-source concordance triangulates passive negotiated facts with active probe evidence.
- Linear database migrations (0012) and type-safe frontend components are in place.
- **No Git commits, pushes, or working tree cleans were performed.**
