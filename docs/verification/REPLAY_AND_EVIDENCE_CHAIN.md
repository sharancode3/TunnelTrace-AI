# Replay and Evidence Chain: Verification & Provenance Report

## Executive Summary & Scope

**Subsystem:** Forensic Replay, Provenance DAG, & Controlled Scenario Execution  
**Assigned Phase:** "Replay and Evidence Chain"  
**Status:** IMPLEMENTED & VERIFIED (20/20 Unit & Integration Tests Passing, Zero Regressions, Production Build Verified)  
**Database Migration:** `0019_replay_lineage_and_provenance.py` (Head of Alembic chain)  

### What This Phase Does:
1. **Enforces Strict Architectural Separation Between Two Distinct Capabilities:**
   - **Forensic Re-Analysis:** Deterministically re-executes packet parsing, normalization, protocol reconstruction, policy evaluation, and scoring over the **exact same immutable packet capture artifact**.
   - **Controlled Scenario Replay:** Re-runs a versioned scenario definition inside the **isolated, owned strongSwan lab namespaces**, validating semantic assertions (SA establishment, bidirectional ping transit, policy outcomes) while explicitly accommodating physical runtime variance (ephemeral SPIs, cryptographic nonces, timestamps, wire jitter).
2. **Fail-Closed Artifact Integrity Gating:** Verifies capture SHA-256 hashes on read prior to execution. If bytes are missing or tampered, execution strictly aborts with a `CaptureIntegrityError` (HTTP 422) and creates no partial records.
3. **Immutable Child Lineage:** Never overwrites historical analysis records or lab manifests. Creates child runs bound via `parent_analysis_id` / `parent_run_id` with parent records preserved.
4. **Secret Redaction & Canonical Config Hashing:** Redacts pre-shared keys, passwords, and private keys (`[REDACTED_SECRET]`) prior to persistence, logging, or hashing. Computes `canonical_config_digest` strictly over sanitized configuration, documented as distinct from secret-bearing bytes.
5. **Relational Evidence Provenance DAG:** Extends the forensic evidence graph with `REPLAY_RUN` (`REPLAYED_FROM`) and `SCENARIO` (`GENERATED_BY`) nodes and edges, sealed into canonical assessment manifests.
6. **Narrow UI Inspection Surface:** Implements the "Replay Lineage" view inside the Evidence screen, exposing capture integrity badges, parent/child lineage cards, pinned toolchain versions, and itemized deterministic diffs.

### What This Phase Does NOT Do:
- Does NOT build new packet sniffers, scanners, or ML classifiers.
- Does NOT replay PCAP traffic onto public, third-party, host, or physical networks (all live executions remain strictly bound to isolated lab network namespaces).
- Does NOT conflate lab scenario re-execution with capture re-analysis.
- Does NOT fabricate execution or mock IDs when Linux namespaces or capture tools are absent; truthfully emits `ENVIRONMENT_MISMATCH` with blocked status.
- Does NOT alter Git history, commit, push, or modify unrelated working-tree files.

---

## 1. Architectural Design & Separation of Concerns

```
                                      [PCAP Artifact / Capture ID]
                                                   │
                       ┌───────────────────────────┴───────────────────────────┐
                       ▼                                                       ▼
        ┌─────────────────────────────┐                         ┌─────────────────────────────┐
        │    Forensic Re-Analysis     │                         │  Controlled Scenario Replay │
        └──────────────┬──────────────┘                         └──────────────┬──────────────┘
                       │                                                       │
         Fail-Closed SHA-256 Check                               Preflight Environment Doctor
         (Rejects tampered bytes)                                (Checks netns, tools, strongSwan)
                       │                                                       │
         Pinned Executable / Policy                              Re-run in Isolated Namespaces
         (tshark, NIST SP 800-77)                                (Local loopback / netns only)
                       │                                                       │
         Deterministic Output Compare                            Semantic Assertion Compare
         (Facts, SAs, Flows, Findings)                           (SA State, Ping Pass, Validation)
                       │                                                       │
         Normalize Volatile Fields                               Accept Physical Runtime Drift
         (Ignore UUIDs, Timestamps)                              (Fresh SPIs, Nonces, Jitter)
                       │                                                       │
                       ▼                                                       ▼
        ┌─────────────────────────────┐                         ┌─────────────────────────────┐
        │  ReplayStatus: EXACT_MATCH  │                         │ ReplayStatus: SEMANTIC_MATCH│
        └─────────────────────────────┘                         └─────────────────────────────┘
```

### Forensic Re-Analysis vs. Scenario Replay Matrix

| Dimension | Forensic Re-Analysis | Controlled Scenario Replay |
| :--- | :--- | :--- |
| **Input Source** | Existing immutable capture file (`Capture.storage_path`) | Versioned scenario YAML (`ScenarioDefinition`) |
| **Target System** | Application analysis pipeline (Dissection, Policy, Scoring) | Isolated Linux kernel namespaces (`netns`) & strongSwan |
| **Integrity Gate** | Exact bitwise SHA-256 match against recorded hash | Preflight toolchain & kernel capability verification |
| **Comparison Target** | Canonical protocol facts, SAs, findings, posture score | Semantic assertions (`sa_established`, `traffic_probe_passed`) |
| **Allowed Tolerances** | Zero tolerance for substantive data; volatile IDs normalized | Runtime nonces, ephemeral SPIs, timestamps, packet timing jitter |
| **Lineage Relationship** | `parent_analysis_id` in `AnalysisRun` | `parent_run_id` in `RunManifest` |
| **Failure State** | `CaptureIntegrityError` (Fail-Closed, HTTP 422) | `ENVIRONMENT_MISMATCH` (Blocked, zero fabrication) |

---

## 2. Provenance Models, Lineage DAG, & Database Schema

### Database Migration: `0019_replay_lineage_and_provenance.py`
The schema extends `analysis_runs` and introduces `replay_comparisons`:
- `analysis_runs.parent_analysis_id`: UUID nullable foreign key referencing `analysis_runs.id` with `ondelete="SET NULL"`.
- `analysis_runs.replay_mode`: String enum (`FORENSIC_REANALYSIS`, `SCENARIO_REPLAY`).
- `analysis_runs.provenance_metadata`: JSON column containing parent timestamps, capture SHA-256, pinned versions, and comparison references.
- `replay_comparisons` table:
  - `id`: UUID primary key.
  - `replay_mode`: String (`FORENSIC_REANALYSIS` or `SCENARIO_REPLAY`).
  - `parent_run_id`: String indexed identifier.
  - `child_run_id`: String indexed identifier.
  - `comparison_status`: String (`EXACT_MATCH`, `SEMANTIC_MATCH`, `DISCREPANCY_DETECTED`, `ENVIRONMENT_MISMATCH`).
  - `artifact_integrity`: String (`VERIFIED`, `MISMATCH`, `NOT_APPLICABLE`).
  - `differences`: JSON structured differences breakdown.
  - `summary`: Text explanation of findings.
  - `metrics`: JSON counters and agreement scores.
  - `created_at`: UTC timestamp.

### Evidence DAG Nodes & Edges
`EvidenceGraphBuilder` creates unbroken cryptographic custody:
- **`REPLAY_RUN` Node:** Linked to the capture node via `REPLAYED_FROM` edge, binding `parent_analysis_id`.
- **`SCENARIO` Node:** Linked to the capture node via `GENERATED_BY` edge, binding `scenario_id` and `scenario_version`.
- **Manifest Sealing:** `AssessmentManifest.create` seals `parent_analysis_id` and `replay_mode` into the assessment SHA-256 digest.

---

## 3. Secret Redaction & Canonical Hashing

Credential exposure in manifests or provenance graphs is strictly prevented by `app.replay.redaction`:
- **Regular Expression Masking:**
  - `secret = "..."` -> `secret = "[REDACTED_SECRET]"`
  - `password = "..."` -> `password = "[REDACTED_SECRET]"`
  - `psk: ...` -> `psk: "[REDACTED_SECRET]"`
  - `-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----` -> `[REDACTED_PRIVATE_KEY_BLOCK]`
- **Recursive Dictionary Redaction:** Automatically masks keys matching `psk`, `secret`, `password`, `token`, `private_key`, `api_key`.
- **Canonical Configuration Digest:**
  - Produces deterministic JSON (sorted keys, normalized LF line endings, stripped trailing spaces).
  - Calculates SHA-256: `compute_canonical_config_digest(config) -> (canonical_text, digest)`.
  - **Security Documentation Notice:** The canonical configuration digest is computed strictly over the redacted text and **does not** represent the cryptographic hash of secret-bearing bytes.

---

## 4. Verification Evidence & Test Execution

### Backend Pytest Suite (`test_replay_and_evidence_chain.py`)
Executed against Python 3.10.11:
```
============================= test session starts =============================
platform win32 -- Python 3.10.11, pytest-8.4.2, pluggy-1.6.0
cachedir: .pytest_cache
rootdir: C:\SHARAN PROJECTS\TunnelTrace AI\backend
configfile: pyproject.toml
plugins: anyio-4.13.0, asyncio-0.26.0

backend\tests\unit\test_replay_and_evidence_chain.py::TestSecretRedactionAndCanonicalHashing::test_redact_secrets_text_psk_and_keys PASSED [  5%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestSecretRedactionAndCanonicalHashing::test_redact_secrets_dict_deep PASSED [ 10%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestSecretRedactionAndCanonicalHashing::test_canonical_config_digest_stability PASSED [ 15%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestCaptureIntegrityVerification::test_capture_integrity_pass PASSED [ 20%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestCaptureIntegrityVerification::test_capture_integrity_mismatch_detected PASSED [ 25%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestCaptureIntegrityVerification::test_capture_integrity_missing_file_detected PASSED [ 30%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestForensicReplayComparator::test_forensic_exact_match PASSED [ 35%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestForensicReplayComparator::test_forensic_discrepancy_detected PASSED [ 40%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestScenarioReplayComparator::test_scenario_semantic_match_with_runtime_variance PASSED [ 45%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestScenarioReplayComparator::test_scenario_semantic_discrepancy PASSED [ 50%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestScenarioReplayComparator::test_scenario_environment_mismatch PASSED [ 55%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestEvidenceDAGReplayNodesAndManifest::test_evidence_builder_with_replay_and_scenario_nodes PASSED [ 60%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestEvidenceDAGReplayNodesAndManifest::test_assessment_manifest_seals_replay_metadata PASSED [ 65%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestReplayServiceExecutionAndLineage::test_execute_forensic_reanalysis_flow PASSED [ 70%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestReplayServiceExecutionAndLineage::test_execute_forensic_reanalysis_tampered_fails_closed PASSED [ 75%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestReplayAPIEndpoints::test_reanalyze_api_endpoint PASSED [ 80%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestReplayAPIEndpoints::test_reanalyze_api_fails_closed_on_integrity_error PASSED [ 85%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestReplayAPIEndpoints::test_get_replay_lineage_api_endpoint PASSED [ 90%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestLabAgentScenarioReplay::test_lab_experiment_manifest_sha256_sealing PASSED [ 95%]
backend\tests\unit\test_replay_and_evidence_chain.py::TestLabAgentScenarioReplay::test_lab_experiment_replay_scenario_preflight_blocks_without_prerequisites PASSED [100%]

======================= 20 passed, 4 warnings in 0.44s ========================
```

### Full Migration Lineage & Regression Checks
```
backend\tests\unit\test_migrations.py::test_alembic_migration_lineage PASSED [ 16%]
backend\tests\unit\test_security_evidence_graph.py::TestEvidenceGraphAndProvenance::test_evidence_graph_building_and_lineage PASSED [ 33%]
backend\tests\unit\test_security_evidence_graph.py::TestAssessmentManifest::test_manifest_sealing_and_tamper_detection PASSED [ 50%]
backend\tests\unit\test_analyses_overview_and_ws.py::TestAnalysesOverviewAndWebSocket::test_list_analyses_endpoint PASSED [ 66%]
backend\tests\unit\test_analyses_overview_and_ws.py::TestAnalysesOverviewAndWebSocket::test_get_analysis_traffic_endpoint PASSED [ 83%]
backend\tests\unit\test_analyses_overview_and_ws.py::TestAnalysesOverviewAndWebSocket::test_realtime_websocket_connection_and_heartbeat PASSED [100%]

======================== 6 passed, 2 warnings in 0.79s ========================
```

### Next.js Production Build
```
▲ Next.js 16.3.6 (Turbopack)
✓ Running next.config.ts took 45ms
✓ Compiled successfully in 1827ms
  Running TypeScript ...
  Finished TypeScript in 8.1s ...
✓ Generating static pages using 11 workers (10/10) in 771ms
  Finalizing page optimization ...
Route (app)
├ ƒ /analyses/[analysisId]/evidence
└ ○ (All routes verified valid)
```

---

## 5. Security Boundaries, Fixtures, & Limitations

1. **`real_tunnel_gcm.pcapng` Role & Provenance:**
   - Fixture path: `tests/fixtures/captures/real_tunnel_gcm.pcapng`
   - File properties: SHA-256 `949531320efb3fefb87ae9f53e6189ba76313b2c6ce09cf2917e70460c5ea2d8`, 3,048 bytes, 12 frames.
   - **Verification Finding:** This capture fixture serves strictly as a protocol dissection validation sample (IKEv2 AES-GCM-128 handshake and bidirectional ESP flow verification). It **does not** contain labeled ML application traffic ground truth and is not represented as such.
2. **Digest vs. Digital Signature Authenticity:**
   - SHA-256 hashing detects modifications and corruption relative to the recorded manifest digest.
   - As documented in the cryptographic provenance requirements, unkeyed digests do not prove author identity or prevent sophisticated man-in-the-middle attacks without an external PKI trust anchor. Future phases may integrate digital signatures over manifests if required by deployment policies.
3. **Environment Prerequisites & Blocked Execution:**
   - Live scenario replay requires a Linux kernel with network namespaces (`ip netns`), strongSwan 5.9+, `swanctl`, and `iproute2`.
   - When executed in environments lacking these prerequisites (e.g. native Windows without WSL2), the testbed agent executes preflight checks and returns `status="BLOCKED"` with `comparison_status="ENVIRONMENT_MISMATCH"`. It **never** fabricates a simulated testbed run or synthetic tunnel state.
