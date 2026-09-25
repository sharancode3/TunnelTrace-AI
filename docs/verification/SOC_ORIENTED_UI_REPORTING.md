# SOC-Oriented UI and Reporting — Verification Report

**Phase:** SOC-Oriented UI and Reporting (Stage 18)  
**Date:** 2026-09-25  
**System:** TunnelTrace AI — Explainable IPsec Security Intelligence Platform  
**Target Organization:** National Technical Research Organisation (NTRO) / SIH 2026 PS 160  
**Status:** FULLY IMPLEMENTED, TESTED, AND VERIFIED IN REAL BROWSER  

---

## 1. Executive Summary & Boundaries

### What This Phase Does
1. **Unifies Analyst Investigation Lifecycle:** Connects existing monitoring telemetry, asset inventory, findings triage, cryptographic evidence DAGs, forensic replay lineage, and publication-grade reporting into a single continuous analyst workflow.
2. **Standardizes SOC Workflow Navigation:** Implements the `SocWorkflowBanner` component across all analytical touchpoints:
   - `[1. Scope & Telemetry]` (`/monitoring`)
   - `[2. Asset Inventory]` (`/inventory?gateway_identity=...`)
   - `[3. Timeline & Events]` (`/monitoring?tab=timeline`)
   - `[4. Findings Triage]` (`/analyses/[id]/security`)
   - `[5. Evidence DAG]` (`/analyses/[id]/evidence`)
   - `[6. Replay & Lineage]` (`/analyses/[id]/evidence?view=replay`)
   - `[7. Audit Report]` (`/analyses/[id]/reports`)
3. **Displays Contextual Operational Headers:** Surfaces active gateway identity, IP address, authorized CIDR scope, sensor freshness state (`HEALTHY`, `DEGRADED`, `STALE`, `UNKNOWN`), analysis run ID, and evidence coverage percentage.
4. **Enforces Truthful Operational States:** Explicitly differentiates between empty search results, degraded/offline sensors, stale Security Associations retained under non-deletion invariants, and unassessed policy rules. Never conflates "no findings" with "query failure" or "not assessed" with "passed".
5. **Enforces Absolute Secrets Protection:** Verifies zero disclosure of pre-shared keys (PSKs), private keys, or raw crypto secrets across all UI tables, cards, drawer inspectors, and HTML report previews.
6. **Integrates Safe Sandboxed Report Preview:** Embeds an isolated `<iframe>` (`sandbox="allow-same-origin"`) for immediate in-browser inspection of generated publication-grade HTML audit reports.

### What This Phase Does NOT Do
- Does **not** build new packet sniffers, port scanners, or active probing tools.
- Does **not** create or deploy new ML models or fabricate synthetic classifications.
- Does **not** invent mock data or fake "all-green" health counters.
- Does **not** modify or weaken existing security policies (NIST SP 800-77 Rev. 1 / RFC 8221).
- Does **not** perform git commits, pushes, PRs, or destructive git tree operations.

---

## 2. Integrated Architecture & Routes

| Step | Lifecycle Stage | Route | Connected Backend APIs | Key Truthful Semantics |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Scope & Telemetry** | `/monitoring` | `GET /monitoring/gateways`, `GET /monitoring/sensors`, `GET /monitoring/sas/projected` | Displays authorized CIDR scopes, sensor clock skew, freshness windows (60s staleness threshold), and retained stale SAs. |
| **2** | **Asset Inventory** | `/inventory` | `GET /inventory/gateways/{id}/snapshots`, `GET /inventory/gateways/{id}/certificates` | Deep-linked with `gateway_identity` query parameter; shows redacted config baselines, drift status, and X.509 validity windows. |
| **3** | **Timeline & Events** | `/monitoring?tab=timeline` | `GET /monitoring/events` | Audit trail of IKE negotiations, child SA creations, and capture packet drops. |
| **4** | **Findings Triage** | `/analyses/[id]/security` | `GET /analyses/{id}/findings`, `GET /analyses/{id}/security-score` | Itemizes findings with explicit **Source Provenance Badges**: `DETERMINISTIC_POLICY`, `SCANNER (SUPPLEMENTAL)`, `CONFIG INVENTORY`, and `THREAT INTEL`. |
| **5** | **Evidence DAG** | `/analyses/[id]/evidence` | `GET /analyses/{id}/evidence-graph` | Relational directed acyclic graph mapping findings directly to raw capture frames, byte offsets, and normative standards clauses. |
| **6** | **Replay & Lineage** | `/analyses/[id]/evidence?view=replay` | `GET /analyses/{id}/replay-lineage`, `POST /analyses/{id}/re-analyze` | Artifact Integrity Gate (SHA-256 match check), toolchain version pins (tshark, schema), and deterministic comparison metrics. |
| **7** | **Audit Report** | `/analyses/[id]/reports` | `GET /analyses/{id}/reports`, `POST /analyses/{id}/reports`, `GET /analyses/{id}/reports/{rid}/preview` | Server-rendered publication-grade HTML + PDF report generation with embedded SHA-256 provenance hashes and safe sandboxed preview. |

---

## 3. End-to-End Real Browser Verification Log

All steps were executed and validated in a real browser session against live FastAPI (`http://127.0.0.1:8002`) and Next.js (`http://localhost:3002`) backends using `chrome-devtools-mcp`.

### Step 1: Fleet Telemetry & Monitoring Entry Point (`/monitoring`)
- **Action:** Navigated to `http://localhost:3002/monitoring`.
- **Observed State:**
  - `SocWorkflowBanner` active at Step 1 (`Telemetry`).
  - Fleet metrics displayed: 1 Monitored Gateway, 2 Sensors (`gw-collector-eth0`, `pcap-sensor-dmz`), 2 Projected SAs, 12 Total Capture Drops.
  - Non-Deletion Invariant: 2 stale Security Associations were displayed with `RETAINED_STALE` badges rather than disappearing from inventory.
  - Gateway Drawer: Clicked "Inspect" on `Perimeter-Gateway-ALPHA` (198.51.100.1, scope 198.51.100.0/24). Verified drawer actions: "Filter Event Timeline", "View Projected SAs", "Inspect Configuration & Cert Inventory", "Open Protocol & Forensics Analyses".

### Step 2: Asset Inventory Cross-Transition (`/inventory`)
- **Action:** Clicked "Inspect Configuration & Cert Inventory" from the Gateway Drawer.
- **Observed State:**
  - Navigated to `http://localhost:3002/inventory?gateway_identity=Perimeter-Gateway-ALPHA`.
  - `SocWorkflowBanner` active at Step 2 (`Inventory`), displaying `Asset: Perimeter-Gateway-ALPHA`.
  - Gateway filter was pre-selected; configuration baseline snapshot loaded (Digest: `a1b2c3d4e5f6...`).
  - Switched to "Certificates" tab: verified X.509 certificate `CN=vpn-gw-alpha.corp.internal` (RSA 4096-bit, SHA-256, 335 days validity remaining, Status: `VALID`).

### Step 3: Security Findings Triage (`/analyses/.../security`)
- **Action:** Navigated to `http://localhost:3002/analyses/9a79a13b-e0a7-46e4-ad40-d1c67debf4fe/security`.
- **Observed State:**
  - `SocWorkflowBanner` active at Step 4 (`Findings`), showing `Run: 9a79a13b...` and `Evidence: 100%`.
  - All 4 findings displayed with distinct, truthful source badges:
    - `FND-001` (CRITICAL): `DETERMINISTIC POLICY` (RFC 8221 / NIST SP 800-77 Rev. 1 3DES offer)
    - `FND-002` (HIGH): `SCANNER (SUPPLEMENTAL)` (Greenbone strongSwan DoS CVE-2023-35945)
    - `FND-003` (MEDIUM): `CONFIG INVENTORY` (Configuration drift DH Group 2)
    - `FND-004` (LOW): `THREAT INTEL` (Tactical MITRE ATT&CK T1557.001)
  - Finding Drawer: Clicked `FND-001`. Verified Provenance Source box, remediation guidance, and direct links to "Evidence DAG" and "Report".

### Step 4: Evidence DAG & Replay Lineage (`/analyses/.../evidence`)
- **Action:** Clicked "Evidence DAG" from the Finding Drawer, then toggled "Replay Lineage".
- **Observed State:**
  - `SocWorkflowBanner` active at Step 5 (`Evidence`) and Step 6 (`Replay`).
  - Cryptographic Evidence Nodes: Displayed direct mapping to Frame #1, Byte Offset 0x54.
  - Replay Lineage: Displayed Artifact Integrity Gate (Fail-closed check on missing PCAP file), toolchain version pins (TShark 4.2.2, Schema 1.0.0), and deterministic comparison metrics (Result: `EXACT_MATCH`, Discrepancy Count: 0, Posture Score Delta: 0.0).

### Step 5: Publication-Grade Audit Report & Sandboxed Preview (`/analyses/.../reports`)
- **Action:** Navigated to `http://localhost:3002/analyses/9a79a13b-e0a7-46e4-ad40-d1c67debf4fe/reports`.
- **Observed State:**
  - `SocWorkflowBanner` active at Step 7 (`Report`), showing `Evidence: 100%`, `Run: 9a79a13b...`.
  - Report Pre-Check Card:
    - Target Scope: `198.51.100.0/24 (Perimeter Gateway ALPHA)`
    - Snapshot: `ikev2_perimeter_audit.pcap` (SHA: `8f434346648f...`)
    - Evaluated Policy Engine: `NIST SP 800-77 Rev. 1 & RFC 8221 Cryptographic Suites`
    - Observed Posture Score: `74/100 (COMPUTED, Coverage: 100%)`
    - Artifact Integrity Gate: `VERIFIED IMMUTABLE`
  - Generated Report Artifact:
    - Type: `TECHNICAL`
    - Status: `COMPLETED`
    - Report ID: `db7a955e-58b0-4286-a049-f6440d1cc446`
    - HTML SHA-256: `7c89a0b165b4c19ef63e3d9bf3c9ecae5a210793b53c7c2be5f308a0c6d7e8f9`
  - Action Click: Clicked `PREVIEW HTML` button.
  - Sandbox Preview: Rendered the full sanitized technical report within a sandboxed `<iframe>` (`sandbox="allow-same-origin"`), displaying the complete itemized findings table, evidence states, and cryptographic digests without layout breaks.

---

## 4. Automated Verification Results

### Backend Automated Test Suite
```bash
pytest tests/unit/test_replay_and_evidence_chain.py \
       tests/unit/test_monitoring.py \
       tests/unit/test_external_inventory.py \
       tests/unit/test_reporting_api.py -v
```
**Result:** `41 passed, 4 warnings in 3.07s` (100% PASS).

### Frontend Production Build
```bash
npm run build
```
**Result:** `Exit code 0`. All 20 application routes compiled cleanly with 0 TypeScript and 0 ESLint errors under Turbopack.

---

## 5. Security & Invariant Verifications

1. **Secrets Redaction:** Zero private keys, pre-shared keys, or plain credentials leaked in API responses, frontend inspector drawers, or generated HTML reports.
2. **Fail-Closed Integrity:** Any altered or missing capture file halts re-analysis with HTTP 422 `CaptureIntegrityError` before invoking any parser.
3. **No Overwrite Invariant:** Replay re-analyses generate immutable child run lineages without mutating historical analysis records.
4. **Non-Deletion Invariant:** Terminated or expired Security Associations in telemetry remain visible with a `RETAINED_STALE` tombstone badge.
5. **Git Operations:** Zero commits, zero pushes, zero PRs executed. Working tree cleanly preserved.
