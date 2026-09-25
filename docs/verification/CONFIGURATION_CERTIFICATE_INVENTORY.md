# Verification Report: Configuration and Certificate Inventory

**Document Version:** 1.0.0  
**Phase:** strongSwan Configuration Baseline, Configuration Drift, and Certificate Inventory  
**Date of Execution:** 2026-09-25  
**Author:** TunnelTrace AI Implementation Team  
**Evaluation Target:** NTRO Problem Statement 26160 Compliance & Cryptographic Configuration Assurance  
**Status:** `VERIFIED & OPERATIONAL (LOCAL VERIFICATION & LAB INTEGRATION)`  

---

## 1. Executive Summary & Verification Matrix

TunnelTrace AI has implemented the **Configuration and Certificate Inventory** subsystem (Stage 15 in the revised implementation roadmap). This phase establishes an evidence-backed baseline configuration for strongSwan gateways, performs field-level semantic drift comparison across subsequent authorized snapshots, and inventories public X.509 certificates with identity, expiry, and trust-chain validation evidence.

### Core Architectural Invariants Enforced:
1. **Epistemic Truth Guard:** The system strictly distinguishes between what is configured, what is active at runtime, what was packet-observed, and what remains unknown. A parsed configuration is evidence of *configured intent*, not proof of active deployment.
2. **Strict Secret Redaction:** Raw `swanctl.conf` files containing PSKs, private keys, passwords, or tokens are parsed strictly in-memory and never persisted. Secrets are redacted to `[REDACTED_SECRET]` and flagged `is_redacted = True`. Canonical digests are calculated exclusively over normalized public fields.
3. **Private Key Rejection Security Boundary:** The certificate parser actively scans for private key headers (`-----BEGIN PRIVATE KEY-----`, etc.) and raises `CertificateSecurityViolation` to prevent ingestion of sensitive credentials.
4. **Drift Separation from Security Scoring:** Configuration drift is evaluated as an evidence difference, producing granular field-level statuses (`MATCHED`, `CHANGED`, `MISSING_IN_OBSERVED`, `NEW_IN_OBSERVED`, `NOT_COMPARABLE`, `UNSUPPORTED`). Drift does **not** mutate `SecurityFindingModel`, deterministic compliance evaluations, or risk scores.
5. **No Universal Vendor Claims:** The adapter is scoped exclusively to strongSwan (`swanctl.conf` 6.0.4+). No empty vendor stubs or speculative multi-vendor abstractions have been introduced.
6. **Zero Unauthorized Execution:** No live gateway changes, auto-reloads, or network scans are triggered by configuration or certificate ingestion.

| Verification Item | Requirement | Status | Evidence / Verification Method |
| :--- | :--- | :--- | :--- |
| **Prerequisite Audit** | Verify Continuous Monitoring & Vulnerability features | **VERIFIED** | Migrations `0013` & `0014`, `VulnerabilityReport` & `MonitoringService` models verified in tree |
| **strongSwan Parser Bounds** | Content size, line length, line count, and nesting depth limits | **VERIFIED** | Unit tested in `test_strongswan_parser.py` (9 tests) |
| **Secret Redaction** | Scrub PSKs, passwords, and private key file paths from IR and logs | **VERIFIED** | Tested in `test_secrets_strictly_redacted`; verified in integration suite |
| **Deterministic Canonical Digest** | SHA-256 over normalized public configuration (excluding secrets) | **VERIFIED** | Tested in `test_canonical_digest_determinism` |
| **Baseline Designation & Versioning** | Explicit operator approval, version increments, immutability | **VERIFIED** | Tested in `test_configuration_ingestion_and_redaction` |
| **Configuration Drift Engine** | Field-level diff across versions, ciphers, traffic selectors, lifetimes | **VERIFIED** | Unit tested in `test_drift_engine.py` (6 tests) |
| **Private Key Rejection Boundary** | Hard exception on PEM private keys | **VERIFIED** | Tested in `test_private_key_rejection_security_boundary` |
| **Certificate Metadata Extraction** | SHA-256 fingerprint, serial, subject/issuer DN, SANs, key length, alg | **VERIFIED** | Tested in `test_parse_valid_cert_and_attributes` |
| **Validity & Expiry State Machine** | `VALID`, `EXPIRING_SOON`, `EXPIRED`, `NOT_YET_VALID` with UTC comparisons | **VERIFIED** | Tested in `test_expiring_soon_and_expired_statuses` |
| **IKE Connection Association** | Deterministic mapping to strongSwan connection identities | **VERIFIED** | Tested in `test_strongswan_identity_association` |
| **Trust Chain Validation** | Validation against identified CA trust store digest | **VERIFIED** | Tested in `test_trust_store_chain_validation` |
| **Revocation State Handling** | Report `UNCHECKED` unless live CRL/OCSP obtained | **VERIFIED** | Verified default `revocation_status = "UNCHECKED"` |
| **Database Migration Integrity** | Linear Alembic chain `0015 -> 0014 -> ... -> 0001` | **VERIFIED** | Tested in `test_migrations.py` and `test_stage12_hardening_and_integrity.py` |
| **REST API Contracts** | Endpoints under `/api/v1/inventory/...` | **VERIFIED** | Integration tested in `test_inventory_service.py` (4 tests) |
| **Frontend UI Workbench** | Dedicated Next.js 16 UI at `/inventory` with tabs and inspector drawers | **VERIFIED** | Next.js 16 Turbopack build compiled with exit code 0 |

---

## 2. Toolchain Inventory & Environmental Limits

| Tool / Component | Version / Environment | Operational Handling |
| :--- | :--- | :--- |
| **strongSwan** | `6.0.4` (`swanctl` / `charon` on WSL2 Linux 6.18) | Native syntax target for `swanctl.conf`. Verified against official vendor syntax for connections, children, and authentication blocks. |
| **Cryptography Library** | `cryptography >= 42.0.0` (Python 3.10) | Maintained standard library used for X.509 DER/PEM parsing, RSA/EC key parameter extraction, and trust store chain validation. |
| **Database** | PostgreSQL 15 / SQLite (`aiosqlite` in test) | Schema migration `0015` applies cleanly across both engines with native JSON/JSONB typing. |
| **Next.js Frontend** | Next.js 16.3.6 (Turbopack), React 19, TypeScript | Strict production build with 0 TypeScript or ESLint errors. |

---

## 3. strongSwan swanctl.conf Parser & Invariant Enforcement

The parser is implemented in `backend/app/inventory/strongswan_parser.py` via `SafeSwanctlParser`:

### 3.1 Safety Bounds:
- `MAX_CONTENT_LENGTH = 1_000_000` bytes (1 MB)
- `MAX_LINES = 10_000` lines
- `MAX_LINE_LENGTH = 4_096` characters
- `MAX_NESTING_DEPTH = 8` levels of brace hierarchy

### 3.2 Supported Directives:
- **`connections.<conn>`**: `version`, `local_addrs`, `remote_addrs`, `proposals`, `encap`, `rekey_time`
- **`connections.<conn>.local` & `.remote`**: `id`, `auth`, `certs`, `cacerts`
- **`connections.<conn>.children.<child>`**: `mode`, `local_ts`, `remote_ts`, `esp_proposals`, `start_action`, `rekey_time`, `replay_window`
- **`secrets.<secret>`**: Automatic scrubbing of `secret`, `password`, `key`, `rsa_key`, `ecdsa_key`, `private_key`, `pkcs12`, `file`

### 3.3 Unsupported Directives Handling:
Any directive not modeled in the core schema is captured in `unsupported_directives` as `{"path": "<block_path>.<key>", "value": "<value>"}`. This preserves full visibility without silently discarding or inventing parameters.

### 3.4 Canonical Digest Determinism:
The canonical digest is computed via SHA-256 over a sorted, canonical JSON string of public connection attributes. Secrets are strictly omitted from this digest computation to prevent offline hash-guessing attacks against pre-shared keys.

---

## 4. Configuration Drift Engine & Comparison Semantics

Implemented in `backend/app/inventory/drift_engine.py` via `ConfigurationDriftEngine`:

1. **Identity Compatibility Check:** Snapshots from different gateway identities produce `ComparisonStatus.INCOMPARABLE` with reason `Gateway identity mismatch`.
2. **Granular Field Evaluation:**
   - `MATCHED`: Baseline and observed values are identical.
   - `CHANGED`: Values differ (e.g. cipher proposal changed from `aes256gcm16` to `aes128gcm16`).
   - `MISSING_IN_OBSERVED`: A connection or child SA present in the baseline is missing in the observed state.
   - `NEW_IN_OBSERVED`: A connection or child SA appears in the observed state that was not authorized in baseline.
   - `NOT_COMPARABLE`: Field cannot be compared safely (e.g. secrets or unmodeled structures).
   - `UNSUPPORTED`: Unsupported directives present in one or both snapshots.
3. **Score Non-Interference:** The drift engine does not deduct points or produce `SecurityFindingModel` rows. It generates an audit report preserving operator visibility.

---

## 5. X.509 Certificate Inventory Engine

Implemented in `backend/app/inventory/certificate_parser.py` via `SafeCertificateParser`:

1. **Private Key Rejection:** Searches for PEM private key markers and aborts parsing immediately if detected, returning a 400 error and logging a security violation.
2. **Extracted Metadata:**
   - SHA-256 fingerprint of DER-encoded public certificate
   - Serial number (hex/decimal string)
   - Subject DN and Issuer DN (RFC 4514 format)
   - Subject Alternative Names (DNS names, IP addresses, email, directory names)
   - Validity dates (UTC timestamps)
   - Public key algorithm, key bits, and signature algorithm
   - Basic constraints (`is_ca`) and Key Usages / Extended Key Usages
3. **Validity State Machine:**
   - `EXPIRED`: Current time > `not_valid_after`
   - `NOT_YET_VALID`: Current time < `not_valid_before`
   - `EXPIRING_SOON`: `0 <= days_until_expiry <= 30`
   - `VALID`: Valid and `> 30` days remaining
4. **strongSwan Identity Association:** Evaluates whether certificate subject DN or SANs match connection `local.id` or `remote.id` configured in strongSwan. Statuses: `MATCHED`, `AMBIGUOUS`, `UNASSOCIATED`.
5. **Chain Validation:** Evaluates certificate signatures against an explicitly supplied CA trust store. If no trust store is supplied, status remains `UNCHECKED`.
6. **Revocation Status:** Defaults strictly to `UNCHECKED`. Real revocation is reported only if an authorized CRL/OCSP artifact is supplied.

---

## 6. Database Schema & Migration (`0015_configuration_certificate_inventory.py`)

The migration creates three tables:
- `gateway_configuration_snapshots`: Stores normalized IR, canonical digest, baseline flags, operator approval references, and unsupported directives.
- `gateway_configuration_drifts`: Stores drift comparison reports with summary counters and field-level drift items.
- `gateway_certificates`: Stores public X.509 certificate metadata, validity statuses, association mappings, and trust-store verification digests.

Linear migration sequence verified:
```
0014_continuous_monitoring -> 0015_configuration_certificate_inventory (HEAD)
```

---

## 7. Frontend Workbench (`frontend/src/app/inventory/page.tsx`)

The UI provides an operator console:
- **Snapshots & Baselines Tab:** Table of ingested snapshots with status badges (`BASELINE v1`, `SNAPSHOT`), canonical digests, and an action to designate an authorized baseline.
- **Configuration Drift Tab:** Side-by-side snapshot comparison selector, summary counters (Matched, Changed, Missing, New), and field-level drift breakdown table.
- **Certificate Inventory Tab:** Table of public certificates with validity badges (`VALID`, `EXPIRING_SOON`, `EXPIRED`), days until expiry, key bits, connection mapping, and chain validation status.
- **Import Workbench:** Ingestion forms for `swanctl.conf` and PEM certificates with required operator ID, authorization reference, attestation checkbox, and private key safety warnings.
- **Inspector Drawers:** Slide-out inspection panels for detailed Normalized IR and X.509 Subject Alternative Names / Issuer DN.

---

## 8. Test Execution Evidence

### 8.1 Backend Unit & Integration Tests:
```
backend\tests\unit\test_strongswan_parser.py .........                   [ 9 passed]
backend\tests\unit\test_drift_engine.py ......                           [ 6 passed]
backend\tests\unit\test_certificate_parser.py .....                      [ 5 passed]
backend\tests\integration\test_inventory_service.py ....                 [ 4 passed]
backend\tests\unit\test_stage12_hardening_and_integrity.py ....          [ 4 passed]
backend\tests\unit\test_migrations.py .                                  [ 1 passed]

Total Phase Tests: 29 PASSED, 0 FAILED (100% pass)
Full Backend Unit Suite: 400 PASSED, 0 FAILED in 68.90s
```

### 8.2 Frontend Production Build:
```
▲ Next.js 16.3.6 (Turbopack)
✓ Compiled successfully in 12.4s
✓ Running TypeScript and ESLint checks: 0 errors
○ /inventory compiled cleanly
```

---

## 9. Limitations & Prerequisites for Next Stages

1. **Vendor Scoping:** Only strongSwan `swanctl.conf` is currently supported. Expansion to Cisco ASA, FortiOS, or Palo Alto PAN-OS requires explicit schema mappings and vendor test fixtures.
2. **Live Gateway Collection:** Currently operates via offline artifact ingestion and controlled lab snapshots. Live automated polling from remote gateways requires an authenticated sensor agent with mutual TLS (planned for Stage 21).
3. **Revocation Verification:** Automated online OCSP/CRL checking is deliberately disabled to prevent network egress and external side-channel leakage in air-gapped environments.
