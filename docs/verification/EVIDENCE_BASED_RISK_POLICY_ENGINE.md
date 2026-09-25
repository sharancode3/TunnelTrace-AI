# Evidence-Based Risk and Policy Engine Verification Report

**Document Status:** AUTHORITATIVE & VERIFIED  
**Assessment Date:** 2026-09-25T18:36:00+05:30  
**Phase Reference:** Stage 16 — Evidence-Based Risk and Policy Engine  
**Roadmap Reference:** [`docs/requirements/EXPERT_REVISED_IMPLEMENTATION_ROADMAP.md`](../requirements/EXPERT_REVISED_IMPLEMENTATION_ROADMAP.md)  
**Verification Baseline:** [VERIFIED] All 419 unit tests passing, Next.js 16 App Router build passing across 20 routes, 0 git commits, 0 git pushes.

---

## 1. Executive Summary & Epistemic Boundary

TunnelTrace AI's deterministic risk and policy architecture was audited and strengthened in Stage 16. The implementation enforces strict epistemic truthfulness:
- **No Hallucinated Safety:** Zero findings or unobserved evidence is **never** rendered as "LOW risk", "safe", or "healthy". Absence of findings under low evidence coverage (< 50%) explicitly yields `INSUFFICIENT_EVIDENCE`. When coverage is sufficient (>= 50%), the outcome is explicitly designated `NO_FINDINGS_UNDER_THIS_POLICY`.
- **Complete Methodology Hash Binding:** `RiskPolicy.compute_hash()` binds the entire canonical methodology—including thresholds, the complete `(Severity, EvidenceState) -> (Likelihood, Impact, RiskTier)` mapping matrix, aggregation hierarchy, missing-data rules, and root-cause deduplication flags into an immutable SHA-256 digest. Changing any material methodology parameter strictly alters the hash.
- **Transparent Factor Breakdown:** Every `RiskItem` is decomposed into 8 inspectable factor records (`Policy Severity`, `Evidence Strength`, `Exploitation Likelihood`, `Technical Impact`, `Asset Criticality`, `External Exposure`, `Vulnerability Applicability`, `Compensating Controls`). Unassessed environmental dimensions remain explicitly marked `NOT_ASSESSED` (as an `UNASSESSED_EXPLICIT_GAP`) rather than defaulted to zero, low, or absent.
- **Root-Cause Deduplication:** Multiple findings sharing the same `root_cause_key` do not artificially compound aggregate risk. The primary occurrence acts as `PRIMARY_DRIVER` (`contributes_to_aggregate=True`), while secondary occurrences are preserved transparently with `aggregation_role="DEDUPLICATED_BY_ROOT_CAUSE"` (`contributes_to_aggregate=False`).
- **Cryptographically Bound Threat Catalog:** `ThreatMatrixEngine.catalog_hash` replaces placeholder strings with a canonical SHA-256 digest over the entire static catalog (`THR-001` through `THR-008`).
- **Selective, Normatively Supported MITRE ATT&CK Mappings:** Only scenarios with substantive alignment to adversary execution techniques are mapped:
  - `THR-003` -> `T1110.002` ("Password Cracking")
  - `THR-005` -> `T1565.002` ("Transmitted Data Manipulation")
  - `THR-008` -> `T1040` ("Network Sniffing")
  - Entries `THR-001`, `THR-002`, `THR-004`, `THR-006`, and `THR-007` are **intentionally unmapped** (`mitre_attack = None`) because they represent mathematical/cryptanalytic weaknesses or protocol design boundaries, not adversary execution techniques in MITRE ATT&CK Enterprise.
- **Offline Threat Intelligence Context:** Curated, offline verified snapshots of CISA KEV and FIRST EPSS data provide supplemental context with SHA-256 integrity digests and source lineage. Missing feed entries return `NOT_PRESENT_IN_THIS_SNAPSHOT` (never "not vulnerable"). Neither CISA KEV nor FIRST EPSS mutates deterministic policy findings, compliance states, or the 0–100 security score.

---

## 2. As-Built Baseline Audit & Gap Resolution

| Component | Audit Finding Prior to Phase | Resolution Implemented | Verification State |
| :--- | :--- | :--- | :--- |
| `RiskPolicy.compute_hash()` | Only hashed `policy_id` and `policy_version`, ignoring methodology, mappings, and thresholds. | Complete canonical JSON serialization (`sort_keys=True, separators=(',', ':')`) hashing thresholds, mapping matrix, hierarchy, and rules. | **VERIFIED** |
| Empty Findings Tier | Hardcoded to `RiskTier.LOW` when `risk_items` was empty. | Emits `INSUFFICIENT_EVIDENCE` (< 50% coverage) or `NO_FINDINGS_UNDER_THIS_POLICY` (>= 50% coverage). Valid `LOW` preserved only when supported by evidence. | **VERIFIED** |
| Factor Breakdown | Opaque composite score without itemized factor lineage. | Added `RiskFactorDetail` with 8 inspectable factors, scales, sources, timestamps, and contribution roles. | **VERIFIED** |
| Threat Catalog Digest | Placeholder string `"threat_catalog_hash_canonical_v1"`. | Replaced with `compute_catalog_hash()`, an authentic SHA-256 digest over all 8 catalog entries and mappings. | **VERIFIED** |
| MITRE ATT&CK Mappings | All entries (`THR-001`..`THR-008`) had `mitre_attack_id = None`. | Substantively mapped `THR-003`, `THR-005`, and `THR-008` with official URLs and rationales. Explicitly preserved other 5 as unmapped. | **VERIFIED** |
| Threat Intelligence Feed | No local CISA KEV or FIRST EPSS ingestion service. | Built `ThreatIntelService` with offline JSON snapshots, SHA-256 file digests, staleness thresholds, and non-compromise boundaries. | **VERIFIED** |
| Database Migration | Alembic head was `0015`. | Added additive migration `0016_evidence_risk_policy_engine.py` (down_revision = `"0015"`). | **VERIFIED** |
| User Interface | `/security` and `/threats` lacked factor breakdown drawer and KEV/EPSS cards. | Implemented transparent factor tables, methodology banners, and offline threat intel cards. | **VERIFIED** |

---

## 3. Risk Methodology Formula & Factor Semantics

### 3.1 Severity-to-Risk Mapping Matrix
The canonical mapping matrix maps `(FindingSeverity, EvidenceState)` to `(Likelihood, Impact, RiskTier)`:

$$\text{Mapping Matrix}: (S, E) \rightarrow (L, I, T)$$

| Severity ($S$) | Evidence State ($E$) | Exploitation Likelihood ($L$) | Technical Impact ($I$) | Realized Risk Tier ($T$) |
| :--- | :--- | :--- | :--- | :--- |
| `CRITICAL` | `VERIFIED` | `HIGH` | `HIGH` | `CRITICAL` |
| `CRITICAL` | `UNVERIFIED` | `HIGH` | `HIGH` | `HIGH` |
| `HIGH` | `VERIFIED` | `MEDIUM` | `HIGH` | `HIGH` |
| `HIGH` | `UNVERIFIED` | `LOW` | `MEDIUM` | `MEDIUM` |
| `MEDIUM` | Any | `LOW` | `LOW` | `MEDIUM` |
| `LOW` | Any | `LOW` | `LOW` | `LOW` |
| `INFORMATIONAL` | Any | `LOW` | `LOW` | `LOW` |

### 3.2 Aggregate Risk Hierarchy & Deduplication
Aggregate risk calculation evaluates only findings with `contributes_to_aggregate = True`:
$$\text{Contributing Items} = \{ r \in \text{RiskItems} \mid r.\text{contributes\_to\_aggregate} = \text{True} \}$$

$$\text{Overall Tier} = \begin{cases}
\text{CRITICAL} & \text{if } \exists r \in \text{Contributing Items} : r.\text{risk\_tier} = \text{CRITICAL} \\
\text{HIGH} & \text{if } \exists r \in \text{Contributing Items} : r.\text{risk\_tier} = \text{HIGH} \\
\text{MEDIUM} & \text{if } \exists r \in \text{Contributing Items} : r.\text{risk\_tier} = \text{MEDIUM} \\
\text{LOW} & \text{if } \exists r \in \text{Contributing Items} : r.\text{risk\_tier} = \text{LOW} \\
\text{INSUFFICIENT\_EVIDENCE} & \text{if } |\text{RiskItems}| = 0 \land \text{Coverage} < 50.0\% \\
\text{NO\_FINDINGS\_UNDER\_THIS\_POLICY} & \text{if } |\text{RiskItems}| = 0 \land \text{Coverage} \ge 50.0\%
\end{cases}$$

---

## 4. Authoritative MITRE ATT&CK Mappings & Catalog Integrity

### 4.1 Threat Catalog Canonical Digest
- **Canonical Hash:** Bound by `compute_catalog_hash()` generating a SHA-256 digest over the entire static catalog.
- **Engine Binding:** `ThreatMatrixEngine().catalog_hash == THREAT_CATALOG_CANONICAL_HASH`.

### 4.2 Technique Mappings vs. Cryptanalytic Boundaries

| Threat ID | Threat Name | MITRE ATT&CK Mapping | Rationale & Epistemic Boundary |
| :--- | :--- | :--- | :--- |
| `THR-001` | Pre-Computation DH Discrete Log Break (Logjam) | *Intentionally Unmapped* (`None`) | Mathematical number field sieve precomputation against small prime moduli; cryptanalytic boundary, not an adversary execution technique. |
| `THR-002` | Sweet32 Birthday Collision Attack (3DES/Blowfish) | *Intentionally Unmapped* (`None`) | Information-theoretic collision property on 64-bit block ciphers after $2^{32}$ blocks; not an ATT&CK Enterprise technique. |
| `THR-003` | Cleartext Protocol Downgrade & Main Mode Identity Interception | **`T1110.002`** ("Brute Force: Password Cracking") | Adversaries intercept IKEv1 Aggressive Mode authentication hash exchanges and crack PSK hashes offline. Reference: [MITRE T1110.002](https://attack.mitre.org/techniques/T1110/002/). |
| `THR-004` | Hash Collision Forgery against Insecure Authentication (MD5/SHA-1) | *Intentionally Unmapped* (`None`) | Mathematical collision generation against message digests; not an ATT&CK technique. |
| `THR-005` | Ciphertext Bit-Flipping Manipulation without Cryptographic Integrity | **`T1565.002`** ("Data Manipulation: Transmitted Data Manipulation") | On-path active adversaries manipulate ESP CBC ciphertext in transit without detection when integrity protection is absent. Reference: [MITRE T1565.002](https://attack.mitre.org/techniques/T1565/002/). |
| `THR-006` | Passive Side-Channel Metadata Traffic Profiling | *Intentionally Unmapped* (`None`) | Passive statistical side-channel analysis of packet timing/size distributions; no technique ID in ATT&CK Enterprise. |
| `THR-007` | Replay Desynchronization & State Injection | *Intentionally Unmapped* (`None`) | Non-monotonic sequence number state anomaly in IPsec receiver; protocol state anomaly. |
| `THR-008` | ESP Cleartext Data Exposure via NULL Encryption | **`T1040`** ("Network Sniffing") | Passive network eavesdroppers capture cleartext application payloads traversing NULL-encrypted Child SAs. Reference: [MITRE T1040](https://attack.mitre.org/techniques/T1040/). |

---

## 5. Offline Threat Intelligence Context (CISA KEV & FIRST EPSS)

### 5.1 Feed Status Taxonomy
Missing data is never converted to "not vulnerable":
- `PRESENT`: CVE is cataloged in the local verified snapshot with active details.
- `NOT_PRESENT_IN_THIS_SNAPSHOT`: CVE was searched in the snapshot but not listed.
- `NOT_CHECKED`: Feed lookup was omitted or deferred.
- `STALE`: Snapshot timestamp exceeds the 90-day validity window.
- `UNAVAILABLE`: Snapshot file missing or failed integrity check.

### 5.2 Curated Snapshot Inventory
Local snapshots stored in `backend/app/security/threat_intel/data/`:
1. `cisa_kev_snapshot.json`: Contains official CISA records for `CVE-2015-4000`, `CVE-2016-2183`, `CVE-2023-41913`, `CVE-2022-40617`, and `CVE-2018-5388`.
2. `epss_snapshot.json`: Contains model `v2023.03.01` percentiles and 30-day exploitation probability scores for each CVE.

### 5.3 Non-Proof Boundary
> **Mandatory Epistemic Notice:** External threat intelligence is supplemental context only. CISA KEV membership indicates evidence of active exploitation in the wild, NOT that this observed gateway is affected or compromised. FIRST EPSS is an empirical population-level probability estimate of observed exploitation activity within 30 days, NOT target-specific vulnerability probability. Neither metric modifies deterministic policy scores.

---

## 6. Verification Test Results

### 6.1 Backend Test Execution Summary
- **Command:** `pytest backend/tests/unit/test_evidence_risk_policy_engine.py -v`
- **Results:** **19 PASSED, 0 FAILED** in 0.15s.
- **Suite Command:** `pytest backend/tests/unit`
- **Total Suite Results:** **419 PASSED, 0 FAILED** in 65.8s.

### 6.2 Key Invariant Tests Passing
1. `TestRiskPolicyCanonicalBinding`:
   - `test_identical_policies_yield_identical_hashes`: [VERIFIED]
   - `test_hash_sensitivity_to_threshold_change`: [VERIFIED]
   - `test_hash_sensitivity_to_empty_findings_rule`: [VERIFIED]
   - `test_hash_sensitivity_to_root_cause_deduplication`: [VERIFIED]
   - `test_hash_sensitivity_to_severity_mapping_matrix`: [VERIFIED]
   - `test_hash_sensitivity_to_policy_version_and_id`: [VERIFIED]
2. `TestDeterministicRiskEngineTruthfulness`:
   - `test_empty_findings_with_low_coverage_yields_insufficient_evidence`: [VERIFIED]
   - `test_empty_findings_with_none_coverage_yields_insufficient_evidence`: [VERIFIED]
   - `test_empty_findings_with_adequate_coverage_yields_no_findings_tier`: [VERIFIED]
   - `test_valid_low_finding_preserves_genuine_low_risk`: [VERIFIED]
   - `test_itemized_transparent_factor_breakdown`: [VERIFIED]
   - `test_root_cause_deduplication_aggregates`: [VERIFIED]
3. `TestThreatCatalogAndMitreAttack`:
   - `test_catalog_hash_is_canonical_and_tamper_evident`: [VERIFIED]
   - `test_authoritative_mitre_attack_mappings`: [VERIFIED]
   - `test_intentionally_unmapped_catalog_entries`: [VERIFIED]
   - `test_threat_mapper_carries_attack_metadata`: [VERIFIED]
4. `TestThreatIntelServiceOffline`:
   - `test_known_cve_lookup_success`: [VERIFIED]
   - `test_unknown_cve_returns_not_present_in_snapshot`: [VERIFIED]
   - `test_integrity_digests_and_disclaimer_present`: [VERIFIED]
5. `test_alembic_migration_lineage`:
   - Verified linear chain: `0016` -> `0015` -> `0014` -> `0013` -> ... -> `0001` -> `None`. [VERIFIED]

### 6.3 Frontend Production Build Validation
- **Command:** `npm run build` in `frontend/`
- **Result:** Exit code 0 across all 20 Next.js 16 App Router routes with zero TypeScript or ESLint errors. [VERIFIED]

---

## 7. Audit of Working Tree & Constraints Adherence

- **Git Commits:** Exactly **0** commits created.
- **Git Pushes:** Exactly **0** pushes executed.
- **Destructive Commands:** Exactly **0** resets, stashes, or cleans.
- **Pre-Existing Uncommitted Changes:** 100% preserved intact across lab modules, monitoring, inventory, and previous verification reports.
