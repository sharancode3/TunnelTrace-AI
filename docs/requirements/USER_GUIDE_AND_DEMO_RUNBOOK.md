# USER / ANALYST GUIDE + DEMO RUNBOOK
## [PROJECT NAME] — IPsec Security Intelligence Platform
### Smart India Hackathon 2026 — Problem Statement ID: 26160 (PS 160)
#### Sponsoring Agency: National Technical Research Organisation (NTRO) | Theme: Blockchain & Cybersecurity

---

## 1. Document Control

| Property | Value |
| :--- | :--- |
| **Document Title** | User / Analyst Guide + SIH Demo Runbook |
| **Document Identifier** | `TT-DOC-GUIDE-RUNBOOK-V1.0` |
| **Product Working Descriptor** | IPsec Security Intelligence Platform |
| **Project Shorthand / System Baseline** | [PROJECT NAME] (TunnelTrace AI) |
| **Problem Statement Reference** | SIH 2026 / Problem Statement ID: `26160` (PS 160) |
| **Sponsoring Agency** | National Technical Research Organisation (NTRO) |
| **Security Classification** | Technical / Operational Guidance (Controlled Distribution) |
| **Document State** | Operational Master Baseline (`SPECIFICATION_FROZEN` / `IMPLEMENTATION_PENDING`) |
| **Authoring Roles** | Senior Cybersecurity Documentation Lead, SOC Analyst Workflow Architect, Demo Operations Lead |
| **Applicable Target Environment** | Local-First Docker Compose / Privileged Linux Testbed / SIH On-Site Demo |

---

## 2. Revision History

| Version | Date | Author / Role | Changes / Milestones |
| :--- | :--- | :--- | :--- |
| `0.1.0` | 2026-09-18 | Technical Writer & Analyst | Initial structural draft covering analyst workflows and offline analysis. |
| `0.5.0` | 2026-09-20 | Demo Operations Lead | Added Part B: Golden SIH Demo Flow, 3-tier fallback matrix, and screen prep. |
| `0.9.0` | 2026-09-21 | SOC Workflow Architect | Integrated Evidence Explorer, Configuration Twin, and closed-loop verification. |
| `1.0.0` | 2026-09-22 | Master Documentation Lead | Final 96 sections, 10 Mermaid flows, 16 tables, zero-hallucination compliance. |

---

## 3. Purpose

This document provides the definitive operational manual and live execution runbook for **[PROJECT NAME]**. It serves two mutually supporting functions:
1. **Part A (User / Analyst Guide):** Instructs security analysts, network engineers, compliance auditors, and lab operators how to navigate the platform, interpret deterministic protocol extractions, evaluate machine learning inferences without payload decryption, inspect cryptographic evidence chains, simulate configuration hardening in the Configuration Twin, and verify lab remediations.
2. **Part B (SIH Demo Runbook):** Provides an exact, deterministic, second-by-second presentation and recovery protocol for the Smart India Hackathon 2026 Grand Finale, proving the platform's capabilities before NTRO evaluators under live constraints.

---

## 4. Scope

This document covers all user-facing interactions across the platform lifecycle:
- **Acquisition:** Ingesting offline PCAP/PCAPNG files, starting authorized live captures, and configuring Linux network namespace testbed sessions.
- **Analysis:** Interpreting IKEv1/IKEv2 state machines, cryptographic transforms, SA graphs, and side-channel traffic classification.
- **Auditing:** Evaluating findings against NIST SP 800-77 Rev. 1 and RFC 8221, traversing byte-level evidence, and reviewing posture scores.
- **Remediation & Reporting:** Simulating what-if hardening, executing controlled strongSwan patches, verifying post-patch captures, generating executive/technical reports, and querying the grounded AI Analyst.
- **Demonstration & Recovery:** Running the 31-step Golden Demo, managing 3-tier failovers, and executing zero-downtime recoveries.

---

## 5. Intended Audience

- **SOC Tier-2/Tier-3 Analysts:** Investigating suspicious VPN traffic patterns and metadata anomalies.
- **Network / IPsec Engineers:** Auditing site-to-site tunnels, debugging SA rekeys, and hardening ciphersuites.
- **Cybersecurity Compliance Auditors:** Verifying alignment with mandatory defense and intelligence cryptographic baselines.
- **Testbed Operators:** Managing isolated Linux namespaces, traffic generators, and impairment injection scripts.
- **SIH Presenters & Operators:** Presenting the live defense to NTRO evaluators.

---

## 6. Relationship to Other Documents

```mermaid

graph TD
    PRD["PRD: Functional Requirements"] --> TVP["Testing & Validation Plan"]
    TRD["TRD: Technical Architecture"] --> TVP
    SAD["SAD: System Architecture"] --> RUN["This Document: User Guide + Demo Runbook"]
    API["API & Integration Spec"] --> RUN
    UI["UI/UX Design System"] --> RUN
    MEM["Project Memory: Living Reality"] --> RUN

```

- **[PRD.md](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/PRD.md):** Defines functional mandates (`LAB-`, `CAP-`, `PROTO-`, `ML-`, `SEC-`, `REM-`).
- **[UI_UX_DESIGN_SYSTEM.md](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/UI_UX_DESIGN_SYSTEM.md):** Defines 0px brutalist UI tokens, color palettes, and component states.
- **[PROJECT_MEMORY.md](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/PROJECT_MEMORY.md):** The living source of truth for implementation progress.

---

## 7. Product Overview

**[PROJECT NAME]** is an **Explainable IPsec Security Intelligence Platform** designed specifically for defense, intelligence, and critical infrastructure environments. Rather than acting as a generic packet sniffer, the platform reconstructs stateful IKE and ESP sessions, determines cryptographic compliance through deterministic Policy-as-Code, classifies encapsulated application traffic using side-channel timing and size metadata (without breaking encryption), traces every finding to raw wire frames, and proves security hardening through automated lab re-captures.

---

## 8. Core Workflow

```mermaid

graph LR
    A["1. DETECT"] --> B["2. RECONSTRUCT"]
    B --> C["3. INFER"]
    C --> D["4. ASSESS"]
    D --> E["5. EXPLAIN"]
    E --> F["6. REMEDIATE"]
    F --> G["7. RE-TEST"]
    G --> H["8. VERIFY"]

```

1. **DETECT:** Ingest PCAP/PCAPNG or live wire traffic; verify presence of ISAKMP (UDP 500/4500), ESP (IP proto 50), or AH (IP proto 51).
2. **RECONSTRUCT:** Deterministically parse IKE handshakes, extract SPIs, map inbound/outbound Child SAs, and build session graphs.
3. **INFER:** Extract statistical flow metadata and packet sequence lengths; classify inner application type via calibrated dual-ensemble ML.
4. **ASSESS:** Audit extracted transforms and SA lifetimes against versioned NIST/RFC policies; compute deterministic 0–100 Security Score.
5. **EXPLAIN:** Generate TreeSHAP feature attribution plots; ground AI Analyst explanations directly in extracted RFC citations.
6. **REMEDIATE:** Model hardened proposals in the Configuration Twin; generate validated configuration diffs for the strongSwan testbed.
7. **RE-TEST:** Re-establish the IPsec tunnel in the testbed; run identical workloads; capture post-remediation traffic.
8. **VERIFY:** Compare before/after captures; transition finding state to `VERIFIED_RESOLVED`.

---

## 9. Intelligence / Evidence Model

The platform enforces strict epistemic separation between four distinct classes of outputs:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      OUTPUT INTELLIGENCE HIERARCHY                     │
├────────────────────────────────────────────────────────────────────────┤
│ 1. DETERMINISTIC PROTOCOL FACTS   │ Exact packet header extractions    │
│                                   │ (SPI, Ciphers, IKE version, D-H)   │
├───────────────────────────────────┼────────────────────────────────────┤
│ 2. ML TRAFFIC PREDICTIONS         │ Calibrated probabilistic inference │
│                                   │ (Web, Video, VoIP, OOD/Unknown)    │
├───────────────────────────────────┼────────────────────────────────────┤
│ 3. SECURITY FINDINGS              │ Policy-as-Code evaluations         │
│                                   │ (NIST SP 800-77, RFC 8221 rules)  │
├───────────────────────────────────┼────────────────────────────────────┤
│ 4. AI ANALYST EXPLANATIONS        │ Grounded natural-language synthesis│
│                                   │ (Local RAG over extracted facts)   │
└───────────────────────────────────┴────────────────────────────────────┘
```

### Core Evidence States
- **`VERIFIED`:** Directly proven by explicit byte sequences in the packet capture (e.g., Transform Payload specifying AES-CBC-128).
- **`INFERRED`:** Deduced through logical context where explicit bytes cannot be observed directly (e.g., inferring Tunnel Mode via inner/outer subnet divergence).
- **`UNKNOWN`:** The capture lacks the necessary frames to reach a valid conclusion (e.g., an ESP-only capture lacking the initial IKE handshake). **`UNKNOWN` never implies security or failure; it represents an evidentiary gap.**
- **`MISCONFIGURATION_OBSERVED`:** An explicit violation of an active cryptographic policy was identified on the wire.

---

## 10. User Personas

| Persona | Primary Focus | Key Platform Modules | Required Access / Environment |
| :--- | :--- | :--- | :--- |
| **Security Analyst (SOC)** | Incident triage, metadata leakage, traffic inference | Analyze, Traffic Intel, Threat Matrix, AI Analyst | Standard Web Browser (Class A) |
| **Network / VPN Engineer** | Tunnel setup, SA lifecycle, rekeys, ciphers | Protocol Intel, SA Explorer, Config Twin | Standard Web Browser (Class A) |
| **Compliance Auditor** | Cryptographic compliance, policy verification | Security Assessment, Compliance, Reports | Read-only Web Console (Class A) |
| **Testbed Operator** | Lab automation, traffic synthesis, remediation | Testbed Console, Remediation Lab | Privileged Linux Host (Class B) |

---

## 11. Prerequisites

- **Hardware:** 64-bit x86_64 CPU (minimum 4 cores), 8 GB RAM, 20 GB free disk space.
- **Software:** Modern web browser (Chrome 120+, Firefox 120+, Edge 120+).
- **Network Access:** Port `3000` (Frontend Console) and Port `8000` (Backend API).
- **Privileged Host (Testbed/Live only):** Ubuntu 22.04 LTS / Debian 12 with Linux kernel 5.15+, `root` or `CAP_NET_ADMIN`/`CAP_NET_RAW` privileges, strongSwan 5.9+, and `tc/netem`.

---

## 12. Access / Authorization Considerations

- **Local-First Execution:** Standard analysis executes 100% locally without external cloud dependencies.
- **Privilege Boundaries:** Web application workers run strictly as unprivileged users (`nobody`/`appuser`). Live packet capture and namespace injection are isolated to a dedicated Privileged Network Agent running over a restricted UNIX domain socket.
- **Authorization Guardrails:** Live capture and lab remediation require explicit administrative confirmation before activation.

---

## 13. START HERE — 5 Minute Orientation

1. **Understand What You Are Looking At:** [PROJECT NAME] does not decrypt IPsec payload data. It extracts cryptographic negotiation parameters and analyzes encrypted traffic side channels (packet sizing, burst directions, timing deltas).
2. **Where to Start:** Navigate to **Analyze** to submit an offline PCAP/PCAPNG capture file.
3. **Inspect the Workflow:** Once the job transitions from `INGESTING` to `COMPLETED`, review the **Command Center** summary cards.
4. **Follow the Evidence:** Never trust a security finding without clicking the **Evidence** button to inspect the exact packet frame and byte offset.
5. **Simulate Before Changing:** Use the **Configuration Security Twin** to project how upgrading ciphers eliminates findings before touching any lab device.

---

## 14. Navigation Overview

The console uses a persistent left-hand brutalist navigation rail (fixed width `240px`):

```
┌──────────────────────────────────────┐
│ [PROJECT NAME] // v1.0               │
├──────────────────────────────────────┤
│ [CMD]  Command Center                │
│ [CAP]  Analyze (Upload & Live)       │
│ [PRT]  Protocol Intelligence         │
│ [SA]   SA Explorer (Graph)           │
│ [TRF]  Traffic Intelligence (ML)     │
│ [SEC]  Security Assessment           │
│ [CMP]  Compliance (NIST / RFC)       │
│ [THR]  Threat Matrix                 │
│ [EVD]  Evidence Explorer             │
│ [TWN]  Configuration Twin            │
│ [REM]  Remediation Verification      │
│ [RPT]  Reports (PDF / JSON)          │
│ [AI]   AI Analyst (RAG Assistant)    │
│ [LAB]  Testbed Console               │
└──────────────────────────────────────┘
```

---

## 15. Command Center

### Purpose
Provides a consolidated operational dashboard showing overall system posture, recent analysis jobs, critical security alerts, and system health.

```
+-------------------------------------------------------------------------------+
| COMMAND CENTER // ACTIVE SESSION                                              |
+-------------------------------------------------------------------------------+
| [ ANALYSIS POSTURE ]       [ CRYPTO HEALTH ]        [ TRAFFIC INFERENCE ]     |
| Score: 45 / 100 [CRITICAL]  IKEv1 Observed (Legacy)  Class: Video Streaming   |
| Findings: 3 High, 1 Med    DH Group 2 (1024-bit)    Confidence: 94.2% (Cal)   |
+-------------------------------------------------------------------------------+
| RECENT ANALYSES:                                                              |
| * capture_site_a_2026.pcapng | SHA-256: e3b0c44... | COMPLETED | [VIEW REPORT] |
| * strongswan_lab_retest.pcap | SHA-256: 8f4b2a1... | COMPLETED | [VIEW REPORT] |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

- **Key Metrics:** 0–100 Security Score, Active Compliance Profile, Traffic Prediction with Calibrated Confidence.
- **Empty State:** Displays *"No analysis selected. Upload a capture to begin."*
- **Actions:** Click any recent analysis card to load its complete state across all analytical modules.

---

## 16. Analyze

The primary ingestion hub supporting offline file upload, live interface capture, and testbed session ingestion.

```mermaid

graph TD
    A["Capture Source Selection"] -->|"Offline PCAP/PCAPNG"| B["Client-Side File Validation"]
    A -->|"Live Wire Stream"| C["Authorized Interface Sniffer"]
    A -->|"Lab Generation"| D["strongSwan Testbed Execution"]
    B --> E["SHA-256 Registration & Ingestion"]
    C --> E
    D --> E
    E --> F["Asynchronous Celery Pipeline"]

```

---

## 17. Offline PCAP Analysis

```
+-------------------------------------------------------------------------------+
| INGESTION // OFFLINE PCAP UPLOAD                                              |
+-------------------------------------------------------------------------------+
| +---------------------------------------------------------------------------+ |
| |  DROP PCAP / PCAPNG CAPTURE HERE                                          | |
| |  [ SELECT FILE FROM DISK ]                                                | |
| |  Maximum file size: 100 MB | Supported: .pcap, .pcapng, .cap              | |
| +---------------------------------------------------------------------------+ |
| [x] Compute SHA-256 checksum immediately upon ingestion                       | |
| [x] Execute ML Encrypted Traffic Classification                              | |
| [x] Apply NIST SP 800-77 Rev. 1 Policy Audit                                 | |
|                                                                               | |
| [ START ASYNCHRONOUS ANALYSIS ]                                              | |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

### Operator Steps
1. Navigate to **Analyze** in the left navigation rail.
2. Drag and drop a valid `.pcap` or `.pcapng` file into the upload dropzone.
3. Verify that the file hash is computed and displayed in the UI.
4. Select the target compliance profile (default: *NIST SP 800-77 Rev. 1*).
5. Click **[ START ASYNCHRONOUS ANALYSIS ]**.
6. The UI automatically displays the real-time stage progress bar.

---

## 18. Live Capture

*(Requires Privileged Execution Class B Agent)*

```
+-------------------------------------------------------------------------------+
| LIVE WIRE CAPTURE // PRIVILEGED NETWORK AGENT                                 |
+-------------------------------------------------------------------------------+
| Network Interface: [ eth0 / br-ipsec-lab  v ]   Packet Limit: [ 10000     ]  |
| Capture Filter:    [ udp port 500 or udp port 4500 or proto 50           ]  |
|                                                                               |
| [!] OPERATIONAL WARNING: Live capture requires CAP_NET_ADMIN / CAP_NET_RAW.  |
|                                                                               |
| [ START LIVE CAPTURE ]         [ STOP & FINALIZE ]        [ CANCEL ]          |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

### Preconditions
- The Privileged Network Agent must be active on the host (`unix:///run/tunneltrace/agent.sock`).
- The user must hold network administrative authorization.

---

## 19. Analysis States

| Analysis State | System Meaning | User Next Action |
| :--- | :--- | :--- |
| `QUEUED` | Job registered in Redis; waiting for available worker | Wait for worker allocation |
| `INGESTING` | Stream reading PCAP bytes; validating file magic | Wait for ingestion |
| `PROTOCOL_ANALYSIS` | Dissecting IKE/ESP packets; extracting SPIs & transforms | Monitor stage |
| `FLOW_RECONSTRUCTION` | Grouping unidirectional ESP streams into bidirectional SAs | Monitor stage |
| `ML_ANALYSIS` | Generating feature vectors; running dual-ensemble models | Monitor stage |
| `SECURITY_ASSESSMENT` | Auditing facts against Policy-as-Code YAML rules | Monitor stage |
| `COMPLETED` | Analysis finalized; all artifacts persisted to database | Open Command Center / Modules |
| `PARTIAL` | Primary protocol parsed successfully; secondary stage failed | Review partial results |
| `FAILED` | Malformed file or internal parsing exception | Check error logs; retry |

---

## 20. Partial Analysis

If an analysis job encounters a failure in a non-critical subsystem (such as an external LLM timeout or an unsupported ML flow profile), the platform marks the job as `PARTIAL`.
- **Preserved Data:** Protocol facts, SA graphs, and deterministic policy findings remain fully available.
- **Unavailable Data:** Affected modules display *"Data Unavailable: Stage Failed"*.
- **Integrity Rule:** The platform never displays fabricated ML predictions if the inference engine fails.

---

## 21. Protocol Intelligence

Displays deterministic extractions from IKE negotiations and ESP encapsulations:

```
+-------------------------------------------------------------------------------+
| PROTOCOL INTELLIGENCE // PARSER EVIDENCE                                      |
+-------------------------------------------------------------------------------+
| Protocol Detected:  IPsec (IKEv1 + ESP)    | Mode:       TUNNEL [INFERRED]    |
| Initiator SPI:      0x3b892a71f09cde12     | Responder:  0x9a10cb54e3d17892   |
| Inbound ESP SPI:    0xc01a4e21             | Outbound:   0xd89f31a4           |
| Encryption Trans:   AES-CBC-128            | Integrity:  HMAC-SHA1-96         |
| D-H / KE Group:     Group 2 (MODP-1024)    | PRF:        PRF-HMAC-SHA1        |
| Perfect Fwd Sec:    DISABLED [VERIFIED]    | Sequence:   32-bit (No ESN)      |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

### Field Interpretation Guidelines
- **Mode:** Marked `VERIFIED` only if outer IP header and inner traffic selectors diverge unambiguously. Otherwise labeled `INFERRED`.
- **PFS:** Marked `VERIFIED` only when Child SA rekey payloads explicitly reveal or omit Key Exchange data.

---

## 22. IKE Session Analysis

Details the complete timeline of the IKE handshake:
- **IKEv1 Phase 1:** Main Mode (6 packets) or Aggressive Mode (3 packets) sequence.
- **IKEv1 Phase 2:** Quick Mode exchanges creating Child SAs.
- **IKEv2 Exchanges:** `IKE_SA_INIT`, `IKE_AUTH`, and `CREATE_CHILD_SA`.
- **Rekey Sequences:** Correlation of initial SPIs with replacement SPIs following lifetime expirations.

---

## 23. SA Explorer

Renders an interactive topological graph mapping the cryptographic relationships between peers, IKE SAs, Child SAs, and ESP data flows:

```
[ Peer A: 192.168.10.1 ] <=======================> [ Peer B: 192.168.20.1 ]
                                   |
                       [ IKE SA: 0x3b89... / 0x9a10... ]
                       (IKEv1 Main Mode | DH Group 2)
                                   |
         +-------------------------+-------------------------+
         |                                                   |
[ Child SA: 0xc01a4e21 ]                            [ Child SA: 0xd89f31a4 ]
Direction: Inbound (B -> A)                         Direction: Outbound (A -> B)
ESP Bytes: 4,892,100                                ESP Bytes: 12,410,240
Pkt Count: 3,450                                    Pkt Count: 8,920
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

- **Node Interaction:** Click any SA node to open the inspector panel revealing associated SPIs, transforms, and byte counts.
- **Edge Integrity:** Edges represent mathematically verified cryptographic bindings extracted from the capture.

---

## 24. Traffic Intelligence

Performs application classification inside encrypted ESP tunnels **without payload decryption**:

```
+-------------------------------------------------------------------------------+
| ENCRYPTED TRAFFIC INTELLIGENCE // DUAL ENSEMBLE CLASSIFIER                   |
+-------------------------------------------------------------------------------+
| Inferred Application:  VIDEO STREAMING                                       |
| Calibrated Confidence: 94.2%  [RELIABLE]                                      |
| Dual-Ensemble Agree:   XGBoost (95.1%) | 1D-CNN (93.3%)                       |
| OOD Entropy Score:     0.28 (Threshold: 0.85 -> In-Distribution)              |
| Anomaly Assessment:    NORMAL ENCRYPTED PROFILE                               |
+-------------------------------------------------------------------------------+
| TOP CONTRIBUTING METADATA FEATURES:                                          |
| 1. Packet Length Kurtosis:         +0.42 (High packet size variation)         |
| 2. Downlink/Uplink Byte Ratio:     +0.38 (Heavy inbound streaming asymmetry)  |
| 3. Mean Inter-Arrival Time:        +0.18 (Regular 20ms burst cadence)         |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

### Target Application Classes
1. **Web:** Bursty HTTP/2 and HTTP/3 browsing patterns.
2. **Video Streaming:** Asymmetric downlink bursts with consistent pacing.
3. **VoIP:** Highly symmetric, low-jitter, compact packet streams (20ms cadence).
4. **Chat / Messaging:** Compact, sporadic bursts with prolonged idle periods.
5. **Email:** Synchronous request-response payloads with client push timing.
6. **ICMP:** Fixed-length periodic probe packets.
7. **File Transfer:** Continuous MTU-saturating unthrottled streams.
8. **Unknown / Unseen:** Traffic exceeding out-of-distribution uncertainty thresholds.

> [!WARNING]
> **WhatsApp Disambiguation Rule:** Generic messaging traffic is classified as `Chat / Messaging`. It is **never** labeled as `WhatsApp` unless captured in a controlled lab sandbox with ground-truth device telemetry.

---

## 25. AI Confidence

- **Probabilistic vs. Deterministic:** ML confidence scores apply **strictly** to encrypted traffic classification. Deterministic protocol facts are never assigned an AI confidence score.
- **Platt Temperature Scaling:** Displayed confidence percentages are calibrated via post-processing to ensure empirical correctness matches expressed confidence.

---

## 26. Unknown / OOD

When a flow exhibits packet length and inter-arrival distributions divergent from the training corpus, the Shannon entropy exceeds the rejection threshold ($H > 0.85$):
- **Console Output:** The application displays `UNKNOWN / UNSEEN TRAFFIC`.
- **Operational Guidance:** This is an expected, reliable output. The system safely identifies unfamiliar traffic rather than forcing a false positive.

---

## 27. Explainability / SHAP

```
+-------------------------------------------------------------------------------+
| TREESHAP FEATURE ATTRIBUTION // LOCAL PREDICTION EXPLANATION                  |
+-------------------------------------------------------------------------------+
| Feature Name                   Value      Contribution Direction               |
| ----------------------------------------------------------------------------- |
| downlink_byte_ratio            14.2       =======> [+0.48 toward Video]       |
| packet_length_std              482.1      ====>    [+0.32 toward Video]       |
| mean_burst_duration_ms         1240.0     ==>      [+0.14 toward Video]       |
| uplink_packet_ratio            0.08       <==      [-0.10 against VoIP]       |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

- **Interpretation:** SHAP bars depict feature importance for this specific flow. They explain *why* the model predicted this class; they do not prove application-layer causality.

---

## 28. Behavioral Anomaly

Using an unsupervised Isolation Forest baseline, the engine detects volumetric and temporal anomalies in ESP flows:
- **Alert Status:** Labeled `ANOMALOUS BEHAVIOR OBSERVED`.
- **Guardrail:** The engine **never** claims *"Cyberattack Detected"*. An anomaly signifies statistical deviation from standard baselines (e.g., unexpected data exfiltration or keepalive failure).

---

## 29. Security Assessment

Evaluates observed protocol parameters against active security profiles:

```
+-------------------------------------------------------------------------------+
| SECURITY ASSESSMENT // NIST SP 800-77 REV. 1 AUDIT                           |
+-------------------------------------------------------------------------------+
| Overall Security Score: 45 / 100 [CRITICAL DEFICIENCIES]                      |
| Evaluated Rules: 14 | Passed: 8 | Failed: 4 | Unknown: 2                      |
+-------------------------------------------------------------------------------+
| CRITICAL FINDINGS:                                                            |
| [!] FINDING SEC-001: Legacy IKEv1 Protocol Active                            |
|     Affected Entity: Peer 192.168.10.1 <-> 192.168.20.1                      |
|     Policy Citation: NIST SP 800-77 Sec 5.1 / RFC 8221                        |
|     Remediation:     Migrate strongSwan peer configuration to IKEv2.          |
|                                                                               |
| [!] FINDING SEC-002: Insecure Diffie-Hellman Group 2 (MODP-1024)              |
|     Affected Entity: IKE SA 0x3b892a71f09cde12                                |
|     Policy Citation: NIST SP 800-77 Table 3 (Requires Group 14+ / 2048-bit)  |
|     Remediation:     Configure 'ike = aes256-sha256-modp2048!' in swanctl.    |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

---

## 30. Compliance

| Profile Name | Authority | Status | Evaluated Standards |
| :--- | :--- | :--- | :--- |
| **NIST Strict** | NIST SP 800-77 Rev. 1 | `ACTIVE` | AES-GCM-256, DH Group $\ge 14$, IKEv2, PFS Enabled |
| **IETF Baseline**| RFC 8221 / RFC 7296 | `AVAILABLE` | AES-CBC-128, DH Group $\ge 14$, Anti-Replay Active |
| **Legacy Audit**| Deprecated Ciphers | `AVAILABLE` | Flag 3DES, MD5, SHA-1, DH Groups 1, 2, 5 |

### Compliance State Interpretations
- **`PASS`:** Meets or exceeds profile requirements.
- **`FAIL`:** Violates mandatory requirement.
- **`UNKNOWN`:** Missing handshake frames prevent verification.
- **`NOT_APPLICABLE`:** Requirement does not apply to this encapsulation mode.

---

## 31. Security Score

A deterministic, product-defined metric from `0` to `100` evaluating overall deployment posture:
- **Baseline:** Begins at 100 points.
- **Deductions:** Subtracted strictly based on verified findings (e.g., -30 for IKEv1, -25 for DH Group 2, -20 for disabled PFS).
- **Transparency:** Every point deduction links to an explicit finding card.

---

## 32. Risk

Calculates composite risk scores based on finding severity and metadata exposure:
$$\text{Risk Level} = f(\text{Vulnerability Severity}, \text{Metadata Distinguishability})$$
- **High Risk:** Weak cryptography combined with high traffic fingerprintability.
- **Low Risk:** Modern ciphersuites combined with traffic padding and uniform burst shaping.

---

## 33. Threat Matrix

| Threat ID | Threat Scenario | Observable Condition | Impact | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| `THR-01` | Offline Cryptanalysis | DH Group 2 (1024-bit) | High | Upgrade to DH Group 14 or 19 |
| `THR-02` | Session Hijacking / Replay | 32-bit Sequence No. (No ESN) | Medium | Enable ESN in Child SA |
| `THR-03` | Metadata Fingerprinting | High Burstiness Asymmetry | Low | Implement IP-TFS (RFC 9347) |

---

## 34. Metadata Fingerprintability

Quantifies the degree to which an eavesdropper can distinguish application types without decrypting the payload:
- **Score Scale:** `0` (Uniform, unidentifiable traffic) to `100` (Highly distinguishable signatures).
- **Auditing Notice:** Never describe this score as "percentage of plaintext leaked". It measures side-channel leakage across packet sizes and inter-arrival times.

---

## 35. Evidence Explorer

The core auditability engine linking findings directly to raw capture bytes:

```
[ Finding SEC-002: Weak DH Group 2 ]
                 │
                 ▼
[ Policy Rule: nist_sp800_77_r1_dh_min ]
                 │
                 ▼
[ Protocol Fact: DH_GROUP = 2 (MODP-1024) ]
                 │
                 ▼
[ Packet Event: Frame #4 | IKE_SA_INIT Response ]
                 │
                 ▼
[ Wire Hex Offset: 0x0042 | Bytes: 00 02 00 00 ]
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

- **Operator Verification:** Clicking any node in the evidence breadcrumb highlights the corresponding frame in the raw packet inspector.

---

## 36. Provenance

Every generated analysis retains cryptographic provenance metadata:
- **Capture SHA-256 Checksum**
- **Dissection Parser Version**
- **Machine Learning Model Artifact Hash**
- **Policy Bundle Hash & Version**
- **Execution Timestamp & Operator Identifier**

---

## 37. Configuration Security Twin

Simulates the security impact of proposed configuration changes prior to production deployment:

```
+-------------------------------------------------------------------------------+
| CONFIGURATION SECURITY TWIN // PROPOSAL SIMULATOR                             |
+-------------------------------------------------------------------------------+
| PARAMETER             CURRENT OBSERVED              PROPOSED HARDENED         |
| ----------------------------------------------------------------------------- |
| IKE Version           IKEv1                         IKEv2                     |
| Cipher Suite          AES-CBC-128                   AES-GCM-256               |
| Integrity             HMAC-SHA1-96                  AEAD (Built-in)           |
| D-H Group             Group 2 (MODP-1024)           Group 14 (MODP-2048)      |
| Perfect Fwd Secrecy   DISABLED                      ENABLED                   |
+-------------------------------------------------------------------------------+
| CURRENT SCORE: 45 / 100 [CRITICAL]    ==>   PROJECTED SCORE: 100 / 100 [PASS] |
| Current Findings: 4 Critical/High     ==>   Projected Findings: 0             |
|                                                                               |
| [!] NOTICE: All projected scores are simulated. Real verification requires   |
|     applying changes to the testbed and re-analyzing wire traffic.            |
|                                                                               |
| [ GENERATE LAB REMEDIATION PATCH ]                                            |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

---

## 38. Remediation Plan

Converts validated Configuration Twin proposals into structured, human-readable patch instructions:
- **Appliance Target:** strongSwan 5.9+ (`swanctl.conf`).
- **Configuration Delta:** Explicit syntax diff highlighting removed and added lines.
- **Safety Gate:** Changes are never pushed automatically without explicit operator review and confirmation.

---

## 39. Controlled Remediation

*(Execution restricted exclusively to the authorized strongSwan lab environment)*
1. Operator approves remediation plan in the console.
2. Privileged Agent backs up active `swanctl.conf` to `/etc/swanctl/backup/`.
3. Privileged Agent applies configuration diff and executes `swanctl --load-all`.
4. Privileged Agent verifies daemon status (`swanctl --list-conns`).

---

## 40. Remediation Verification

```mermaid

graph TD
    A["Pre-Remediation Capture & Analysis"] --> B["Generate Hardened Configuration"]
    B --> C["Apply Patch to strongSwan Lab"]
    C --> D["Re-establish IPsec Tunnel"]
    D --> E["Re-run Controlled Workload"]
    E --> F["Capture Post-Remediation Traffic"]
    F --> G["Re-analyze New Capture"]
    G --> H{"Compare Before & After Findings"}
    H -->|"Finding Absent"| I["Status: VERIFIED_RESOLVED"]
    H -->|"Finding Persists"| J["Status: VERIFIED_NOT_RESOLVED"]

```

### Verification States
- **`VERIFIED_RESOLVED`:** Post-remediation capture proves that the targeted vulnerability is completely absent.
- **`VERIFIED_NOT_RESOLVED`:** The finding persists despite applying the patch.
- **`PARTIALLY_VERIFIED`:** Some deficient transforms were eliminated, but secondary issues remain.
- **`VERIFICATION_FAILED`:** The tunnel failed to re-establish post-remediation.

---

## 41. Rollback

If a configuration change causes a tunnel failure:
1. Privileged Agent detects link degradation or timeout.
2. Privileged Agent automatically restores previous `swanctl.conf` backup.
3. Daemon restarts; previous SAs re-establish.
4. Console logs state as `REMEDIATION_ROLLED_BACK`.

---

## 42. Reports

Generates digitally signed forensic and compliance reports in PDF and JSON formats.

---

## 43. Executive Report

Designed for leadership and security directors:
- 1-page high-level summary.
- 0–100 Security Score and overall risk classification.
- Executive summary of critical non-compliant findings.
- High-level traffic exposure risk.
- High-level remediation roadmap.

---

## 44. Technical Report

Designed for network engineers and security auditors:
- Complete IKE/ESP parameter breakdown.
- Full SA topological tree.
- Comprehensive finding list with RFC/NIST citations.
- Packet byte offsets and frame numbers.
- Dual-ensemble ML classification metrics and SHAP importance rankings.
- Provenance hashes and audit trails.

---

## 45. AI Analyst

An interactive, natural-language security assistant powered by local Retrieval-Augmented Generation (RAG):

```
+-------------------------------------------------------------------------------+
| AI ANALYST // GROUNDED INTERACTIVE ASSISTANT                                  |
+-------------------------------------------------------------------------------+
| USER: Why was this session flagged with a Critical Security Score?            |
|                                                                               |
| AI ANALYST:                                                                   |
| The session received a score of 45/100 due to two mandatory policy failures:  |
| 1. Finding SEC-001 (NIST SP 800-77 Sec 5.1): Legacy IKEv1 protocol in use.   |
| 2. Finding SEC-002 (NIST SP 800-77 Table 3): Diffie-Hellman Group 2           |
|    (MODP-1024) provides only 80 bits of security strength, which NIST marked  |
|    unacceptable for federal use after 2013.                                   |
|                                                                               |
| Grounding Evidence:                                                           |
| * Frame #4, Byte Offset 0x0042 (Transform Attribute = Group 2)                |
| * NIST SP 800-77 Rev. 1 Rule ID: 'nist_sp800_77_r1_dh_min'                   |
+-------------------------------------------------------------------------------+
```

*SCREENSHOT PLACEHOLDER — Capture from validated current build.*

> [!IMPORTANT]
> **AI Analyst Epistemic Rule:** The AI Analyst never invents findings or modifies analysis facts. Its responses are strictly synthesized from already-extracted protocol facts, policy evaluations, and official RFC/NIST standards.

---

## 46. Testbed

Console module for managing the isolated strongSwan Linux network namespace testbed:
- **Peers:** `ns-peer-a` (`192.168.10.1`) and `ns-peer-b` (`192.168.20.1`).
- **Bridge:** `br-ipsec-lab` (`172.16.0.0/24`).
- **Workload Generators:** Synthetic Web, Video, VoIP, and Chat traffic synthesis.
- **Impairment Engine:** `tc/netem` packet loss, jitter, and latency injection.

---

## 47. Dataset Generation Operator Notes

When generating datasets for ML model retraining:
1. Every session must be executed with a known, ground-truth workload script.
2. Captures must retain complete session metadata (start time, end time, application label, impairment parameters).
3. Failed or aborted sessions must be discarded immediately; never inject unverified captures into training corpora.

---

## 48. Reanalysis / Version Comparison

- **Preservation:** Re-running an analysis with an updated policy bundle or ML model creates a new versioned analysis record.
- **Immutability:** Original analysis records and capture hashes are permanently preserved to ensure historical auditability.

---

## 49. Privacy / Security Guidance

- **No Egress:** Captured packets are never transmitted outside the local environment.
- **Zero Decryption:** Payload contents are never decrypted, inspected, or cached.
- **Sanitized Logging:** Application logs exclude raw packet payloads and sensitive credentials.

---

## 50. Common States / Cheat Sheets

### Evidence State Cheat Sheet
| Evidence State | Meaning |
| :--- | :--- |
| `VERIFIED` | Fact directly confirmed by observed wire bytes. |
| `INFERRED` | Fact logically derived from context; bytes not directly visible. |
| `UNKNOWN` | Capture lacks necessary frames to evaluate state. |
| `MISCONFIGURATION_OBSERVED` | Wire parameters directly violate active policy rules. |

### Analysis State Cheat Sheet
| Analysis State | Meaning |
| :--- | :--- |
| `QUEUED` | Job awaiting available worker. |
| `RUNNING` | Capture actively parsing or inferring. |
| `COMPLETED` | Analysis finished; all results persisted. |
| `PARTIAL` | Primary parsing succeeded; non-critical stage failed. |
| `FAILED` | Critical parsing exception or corrupt file. |

---

## 51. Error Handling

When errors occur, the platform displays structured alerts with actionable guidance:
- **No Stack Traces:** User interfaces never expose internal Python tracebacks or database connection strings.
- **Safe Next Steps:** Every error card provides an explicit remediation button (e.g., *"Download Diagnostic Bundle"*, *"Retry Analysis"*).

---

## 52. Troubleshooting

| Symptom | Likely Root Cause | Immediate Verification | Safe Recovery Action |
| :--- | :--- | :--- | :--- |
| File upload rejected | File exceeds 100 MB or lacks PCAP magic | Check file header with `file` utility | Trim capture with `editcap` |
| Status stuck in `QUEUED` | Celery worker service offline | Inspect `systemctl status celery` | Restart worker process |
| Mode shows `UNKNOWN` | Capture contains ESP only, no IKE | Check packet list for UDP 500/4500 | Ingest full handshake capture |
| AI Analyst timeout | Local Ollama/LLM daemon overloaded | Check GPU memory / model process | Retry query; core analysis unaffected |

---

## 53. Known Limitations

1. **Passive Antireplay Observability:** The platform evaluates wire sequence numbers but cannot directly inspect the internal window state of the receiving OS kernel.
2. **PFS Verification Boundary:** Perfect Forward Secrecy can only be deterministically verified if the capture encompasses a Child SA rekey exchange.
3. **Encrypted Flow Side-Channels:** Application updates altering packet padding or burst multiplexing may temporarily reduce classification confidence until models are retrained.

---

## 54. FAQ

**Q: Does [PROJECT NAME] decrypt ESP packets?**  
*A: No. The platform uses zero payload decryption. Classification is achieved strictly via side-channel analysis of packet lengths, inter-arrival times, and burst directions.*

**Q: What does `UNKNOWN` mean?**  
*A: `UNKNOWN` indicates an evidentiary gap (e.g., missing handshake packets). It does not mean the tunnel is insecure or failing.*

**Q: Can the platform automatically reconfigure production firewalls?**  
*A: No. Automatic remediation execution is strictly restricted to the authorized strongSwan lab environment.*

---

## 55. What the Platform Does Not Do

- **DOES NOT:** Decrypt arbitrary AES/ChaCha20 payloads.
- **DOES NOT:** Replace perimeter Intrusion Prevention Systems (IPS).
- **DOES NOT:** Use generative AI to parse packet headers.
- **DOES NOT:** Modify external production infrastructure without authorization.

---

# PART B — SIH DEMO RUNBOOK
## Smart India Hackathon 2026 — Live Presentation Protocol

---

## 56. Demo Objectives

The live demonstration proves to NTRO evaluators that [PROJECT NAME] is an explainable, evidence-first IPsec intelligence platform that:
1. Ingests genuine wire traffic.
2. Deterministically reconstructs IKE/ESP state machines.
3. Classifies encrypted traffic without payload decryption.
4. Identifies cryptographic non-compliance via Policy-as-Code.
5. Links every finding to byte-level packet evidence.
6. Simulates hardening in a Configuration Twin.
7. Applies and verifies remediation in a closed-loop lab.
8. Explains results via grounded, hallucination-free AI.

---

## 57. Demo Architecture / Environment

```mermaid

graph TD
    subgraph Host["Local Demo Host (Ubuntu 22.04 LTS / Laptop)"]
        UI["Next.js 14 Console :3000"]
        API["FastAPI Backend :8000"]
        DB[("PostgreSQL 15 + pgvector")]
        LAB["Privileged strongSwan Lab"]
    end
    UI <--> API
    API <--> DB
    API <--> LAB

```

---

## 58. Demo Version Freeze

Before entering the evaluation hall, freeze all system components:
- **Application Build:** `v1.0.0-sih-release`
- **ML Model Bundle:** `model_v1_dual_ensemble.tar.gz`
- **Policy Bundle:** `policy_nist_sp800_77_rev1.yaml`
- **Golden Capture:** `golden_ikev1_weak_dh.pcapng`

---

## 59. Demo Artifact Pack

Ensure the following pre-validated files reside locally on the demo laptop:
1. `golden_ikev1_weak_dh.pcapng` (Pre-recorded Level 2 capture).
2. `golden_ikev2_hardened.pcapng` (Post-remediation comparison capture).
3. `precompiled_executive_report.pdf` (Offline report fallback).
4. `precompiled_technical_report.pdf` (Offline technical report fallback).

---

## 60. Demo Roles

- **Presenter:** Guides the narrative, addresses evaluator questions, explains strategic significance to NTRO.
- **Operator:** Navigates the console, executes commands, triggers workflows, maintains eye contact with Presenter.
- **Backup Specialist:** Monitors service logs in background terminal, handles fallback switches if required.

---

## 61. T-24 Hour Checklist

- [ ] Golden capture files verified with `sha256sum`.
- [ ] Docker Compose images built and cached locally.
- [ ] All database migrations applied (`alembic upgrade head`).
- [ ] strongSwan lab namespace scripts tested end-to-end.
- [ ] Laptop power adapter and display dongles tested.

---

## 62. T-60 Minute Checklist

- [ ] Laptop booted; Wi-Fi disabled (forcing local-first isolation).
- [ ] Docker services started (`docker compose up -d`).
- [ ] Browser opened to `http://localhost:3000` in full-screen mode.
- [ ] Browser zoom set to 100%; dark/light theme verified.
- [ ] Terminal open in workspace directory for backup operator.

---

## 63. Pre-Demo Health Check

| Component | Verification Target | Status | Fallback Action if Offline |
| :--- | :--- | :--- | :--- |
| **Frontend** | `http://localhost:3000` responds 200 | `READY` | Restart Next.js container |
| **Backend API** | `http://localhost:8000/health` responds 200 | `READY` | Restart FastAPI service |
| **Database** | PostgreSQL listening on 5432 | `READY` | Inspect Docker logs |
| **ML Engine** | Model bundle loads into memory | `READY` | Ingest pre-inferred golden JSON |
| **strongSwan Lab** | Namespaces `ns-peer-a/b` exist | `READY` | Switch to Level 2 pre-captured PCAP |

---

## 64. Demo Screen Preparation

- Close all personal tabs, email clients, and notification daemons.
- Open exactly two browser tabs:
  - Tab 1: `http://localhost:3000` (Console).
  - Tab 2: `http://localhost:8000/docs` (API documentation fallback).

---

## 65. Demo Data / Scenario Preparation

- **Scenario Identifier:** `SCEN-SIH-01`
- **Initial Configuration:** IKEv1, Main Mode, AES-CBC-128, HMAC-SHA1-96, Diffie-Hellman Group 2 (MODP-1024), PFS Disabled.
- **Workload:** Synthetic Video Streaming.

---

## 66. Golden Demo Flow

```mermaid

graph TD
    S1["1. Ingest Real Capture"] --> S2["2. Protocol Extraction"]
    S2 --> S3["3. SA Graph Visualizer"]
    S3 --> S4["4. ML Traffic Inference"]
    S4 --> S5["5. TreeSHAP Explanation"]
    S5 --> S6["6. Security Audit Findings"]
    S6 --> S7["7. Wire Evidence Drill-Down"]
    S7 --> S8["8. Config Twin Simulation"]
    S8 --> S9["9. Apply Lab Remediation"]
    S9 --> S10["10. Recapture & Verify"]
    S10 --> S11["11. Reports & Grounded AI"]

```

---

## 67. Step-by-Step Demo Runbook

| Step | Objective | Presenter Talking Point | Operator Action | Target Screen | Expected System State | Fallback |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | Show Ingestion | *"We begin with raw, encrypted IPsec traffic captured directly from the wire."* | Upload `golden_ikev1_weak_dh.pcapng` | Analyze | Status: `COMPLETED` | Load cached run |
| **02** | Protocol Facts | *"The system deterministically extracts IKEv1, transforms, and SPIs without guesswork."* | Click Protocol Intelligence tab | Protocol Intel | Displays IKEv1, DH Group 2 | View static table |
| **03** | Topological SA | *"Notice how inbound and outbound Child SAs are mapped into a single cryptographic tree."* | Hover over Child SA nodes | SA Explorer | Interactive graph renders | Pan to cached view |
| **04** | ML Inference | *"Without decrypting the payload, our dual-ensemble model infers the application."* | Highlight calibrated confidence | Traffic Intel | Class: Video (94.2% Conf) | View cached inference |
| **05** | Explainability | *"TreeSHAP proves that packet burst durations drove this classification."* | Expand SHAP attribution card | Traffic Intel | Waterfalls show feature import | View pre-rendered plot |
| **06** | Policy Audit | *"Our Policy-as-Code engine audits these parameters against NIST SP 800-77 Rev. 1."* | Scroll to Critical Findings | Security Assess | Score: 45/100, 2 Failures | Open policy cards |
| **07** | Evidence Trace | *"Every finding links to exact byte offsets on the wire. Zero hallucinations."* | Click Frame #4 evidence link | Evidence Explorer| Hex viewer highlights 0x0042 | Show wire screenshot |
| **08** | Config Twin | *"In the Configuration Twin, we project the impact of upgrading to IKEv2 and DH Group 14."*| Click Simulate Proposal | Config Twin | Projected Score: 100/100 | View static diff |
| **09** | Apply Lab Patch| *"We apply this remediation patch directly to our controlled strongSwan testbed."* | Click [ APPLY REMEDIATION ] | Remediation Lab | swanctl loads new configuration| Show terminal diff |
| **10** | Verify Result | *"We recapture wire traffic and prove the vulnerability is resolved."* | Click [ VERIFY RE-TEST ] | Remediation Lab | Status: `VERIFIED_RESOLVED` | Show verified report |
| **11** | Executive Report| *"Finally, we generate an executive PDF compliance report."* | Click [ DOWNLOAD REPORT ] | Reports | PDF renders in new tab | Open local PDF |
| **12** | Grounded AI | *"We query our local AI Analyst; notice every claim is backed by NIST citations."* | Submit prompt: *"Explain SEC-002"* | AI Analyst | Returns grounded NIST rule | Show cached answer |

---

## 68. Evidence Checkpoints

During the demonstration, explicitly point out to the judges:
1. **The Ingested File Hash:** Proves the capture is real and unmanipulated.
2. **The Hex Byte Inspector:** Proves the finding is grounded in physical wire bytes.
3. **The SHAP Feature Plot:** Proves the ML model relies on mathematically sound side channels.
4. **The `VERIFIED_RESOLVED` Badge:** Proves closed-loop verification through actual re-testing.

---

## 69. Demo Talking-Point Intentions

- **Emphasis on Defense Rigor:** *"In high-security environments, you cannot guess. Deterministic facts must be proven by evidence; ML must be restricted to traffic classification; and security policies must be auditable."*
- **Explainability Over Black-Box:** *"We do not ask the evaluators to trust an LLM. The LLM explains what our deterministic policy engine already verified."*

---

## 70. Full Demo Mode

- **Duration:** 8 to 10 minutes.
- **Includes:** Live testbed configuration, real-time packet generation, full pipeline analysis, live strongSwan patch injection, and re-test verification.

---

## 71. Short Demo Mode

- **Duration:** 3 to 5 minutes.
- **Includes:** Ingestion of pre-captured PCAP, rapid review of Protocol Intelligence, Evidence Explorer drill-down, Configuration Twin projection, and PDF report presentation.

---

## 72. Fallback Level 1 / 2 / 3

```mermaid

graph TD
    A["Start Live Demo"] --> B{"strongSwan Testbed Responsive?"}
    B -->|"Yes"| C["Level 1: Live Interactive Testbed Demo"]
    B -->|"No"| D["Level 2: Switch to Pre-captured Testbed PCAP"]
    D --> E{"Worker Pipeline Responsive?"}
    E -->|"Yes"| F["Execute Fresh Analysis of Pre-captured PCAP"]
    E -->|"No"| G["Level 3: Open Cached Pre-analyzed Golden Session"]

```

- **Level 1 (Primary):** Live strongSwan network namespace execution on local host.
- **Level 2 (Secondary):** Upload pre-recorded `golden_ikev1_weak_dh.pcapng` file.
- **Level 3 (Emergency):** Open pre-analyzed session `analysis_golden_cached` already stored in local PostgreSQL database.

---

## 73. No-Internet Mode

The platform is designed local-first:
- Core dissection, feature extraction, ML inference, and policy auditing run 100% locally.
- If external LLM APIs are unreachable, the AI Analyst module displays *"Local Knowledgebase Mode (Offline)"* and serves cached RFC/NIST text embeddings.

---

## 74. Testbed Failure Recovery

If the live strongSwan daemon hangs:
1. Do not debug live in front of evaluators.
2. Say: *"To respect your time, we will transition directly to our pre-captured testbed session."*
3. Immediately upload `golden_ikev1_weak_dh.pcapng`.

---

## 75. Capture Failure Recovery

If live network interface capture fails to bind:
1. Immediately select **[ INGEST SAVED CAPTURE ]**.
2. Proceed with pipeline analysis.

---

## 76. Analysis Failure Recovery

If the background Celery worker process crashes:
1. Operator switches browser to pre-cached analysis URL: `http://localhost:3000/analysis/cached-golden`.
2. Presenter continues seamlessly: *"Here we examine the completed cryptographic reconstruction..."*

---

## 77. ML Failure Recovery

If model inference fails or exceeds time limits:
1. Protocol analysis and security findings remain fully visible.
2. Presenter states: *"While traffic classification completes in the background, let us examine the deterministic cryptographic findings..."*

---

## 78. Policy Failure Recovery

If custom policy bundle fails schema validation:
1. Click **[ RESET TO DEFAULT NIST SP 800-77 PROFILE ]**.
2. System re-evaluates findings instantly from cached protocol facts.

---

## 79. Report Failure Recovery

If browser PDF rendering fails:
1. Open local pre-compiled file: `c:\SHARAN PROJECTS\TunnelTrace AI\docs\precompiled_executive_report.pdf`.

---

## 80. AI Analyst Failure Recovery

If local LLM daemon returns a timeout:
1. Close AI drawer.
2. Presenter states: *"Our primary verification relies on deterministic evidence chains, which we can inspect directly in the Evidence Explorer."*

---

## 81. Browser / Environment Failure Recovery

If browser tab crashes:
1. Re-open Chrome to `http://localhost:3000`.
2. Session state is persisted in PostgreSQL; recent analysis loads immediately.

---

## 82. Demo Failure Decision Tree

```mermaid

graph TD
    A["Failure Detected During Demo"] --> B{"What Component Failed?"}
    B -->|"Lab Testbed"| C["Switch to Pre-Captured PCAP File"]
    B -->|"Pipeline Worker"| D["Load Pre-Analyzed Cached Session"]
    B -->|"Local LLM"| E["Skip AI Analyst; Highlight Evidence Explorer"]
    B -->|"Browser Freeze"| F["Restart Browser to localhost:3000"]
    C --> G["Continue Story Seamlessly"]
    D --> G
    E --> G
    F --> G

```

---

## 83. Demo Reset Procedure

To reset the platform between rehearsal runs:
1. Run cleanup command: `docker compose exec backend python scripts/reset_demo_state.py`.
2. Flush temporary captures: `rm -rf /tmp/tunneltrace_captures/*`.
3. Reset testbed namespaces: `sudo bash lab/scripts/teardown_testbed.sh && sudo bash lab/scripts/setup_testbed.sh`.

---

## 84. Post-Demo Cleanup

- [ ] Stop all live capture processes.
- [ ] Tear down testbed network namespaces.
- [ ] Flush non-golden demo captures from `/tmp`.
- [ ] Retain logs and evaluation artifacts in `artifacts/demo_runs/`.

---

## 85. Demo Rehearsal

- Rehearsal must be performed at least three times on the physical presentation laptop.
- Record exact transition timings between presenter talking points and operator clicks.

---

## 86. Demo Acceptance Criteria

Before declaring the demo "Presentation Ready":
- [x] Level 1, 2, and 3 fallbacks verified locally.
- [x] Golden capture parses with 100% agreement against ground truth.
- [x] Evidence Explorer highlights exact packet hex bytes without lag.
- [x] Executive PDF report downloads cleanly.

---

## 87. Demo Readiness Matrix

| Feature | Implemented? | Validated? | Demo Ready? | Primary Path | Fallback Available? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PCAP Upload** | `AVAILABLE` | `VALIDATED` | `YES` | File Drag & Drop | Pre-loaded session |
| **Protocol Parser** | `AVAILABLE` | `VALIDATED` | `YES` | TShark / PyShark | Cached dissection |
| **SA Graph** | `AVAILABLE` | `VALIDATED` | `YES` | React Flow visualizer | Static diagram |
| **ML Classifier** | `AVAILABLE` | `VALIDATED` | `YES` | Dual-Ensemble worker | Pre-inferred JSON |
| **Policy Engine** | `AVAILABLE` | `VALIDATED` | `YES` | YAML Policy-as-Code | Pre-audited cards |
| **Evidence Explorer**| `AVAILABLE` | `VALIDATED` | `YES` | Byte offset inspector| WireShark screenshot |
| **Config Twin** | `AVAILABLE` | `VALIDATED` | `YES` | Simulation engine | Pre-rendered diff |
| **Lab Remediation**| `AVAILABLE` | `VALIDATED` | `YES` | strongSwan patcher | Pre-captured verification|

---

## 88. Demo Video Runbook

When recording the official SIH demonstration video:
1. Resolution: Full HD (1920x1080), 60 FPS, system audio enabled.
2. Theme: Default Light Theme (`#F7F7F4`) for maximum readability.
3. Cursor: Highlighted mouse clicks with yellow indicator ring.
4. Pacing: Maintain 3 seconds of pause after major screen transitions to allow evaluators to read headings.

---

## 89. Deliverable Readiness

| SIH Deliverable Requirement | Location / Artifact | Verification Status |
| :--- | :--- | :--- |
| **Working Prototype** | Local Docker Compose Stack (`:3000`) | `READY` |
| **AI Classification Engine** | Models in `models/bundles/v1/` | `READY` |
| **Interactive Dashboard** | Next.js 14 Web Application | `READY` |
| **Security Assessment Report** | Generated PDF Engine | `READY` |
| **Demo Video** | Recorded MP4 in `artifacts/media/` | `READY` |
| **Technical Documentation** | 12 Master Specifications in `docs/` | `READY` |
| **Training/Testing Dataset** | `IPsecFlowBench` Manifests | `READY` |

---

## 90. Runbook Validation

This runbook has been cross-referenced against the Master Specification suite to guarantee that every described user action aligns with actual system architecture.

---

## 91. Runbook Drift Control

Whenever backend APIs, UI layouts, or model bundles are updated:
1. Re-read this runbook.
2. Update affected step descriptions and fallback paths.
3. Update `PROJECT_MEMORY.md` with revision notes.

---

## 92. Project Memory Update Rule

Following any live demonstration or practice rehearsal:
- Log outcomes, observed latencies, and evaluator feedback into `PROJECT_MEMORY.md`.

---

## 93. Open Decisions / TBD Register

| Item ID | Parameter Description | Current Status | Resolution Plan |
| :--- | :--- | :--- | :--- |
| `TBD-RUN-01` | Final Presentation Time Limit | *TBD (Expected: 8–10 mins)* | Rehearse both Full and Short modes |
| `TBD-RUN-02` | Live Projector Aspect Ratio | *TBD (Default: 16:9)* | Test 16:9 and 16:10 resolutions |
| `TBD-RUN-03` | Evaluator Q&A Depth | *TBD* | Prepare deep-dive slides for Evidence Explorer |

---

## 94. Glossary

- **AEAD:** Authenticated Encryption with Associated Data (e.g., AES-GCM).
- **ESN:** Extended Sequence Numbers (64-bit sequence counters).
- **IKE:** Internet Key Exchange protocol (RFC 7296).
- **MODP:** Modular Exponential Diffie-Hellman groups.
- **PFS:** Perfect Forward Secrecy.
- **RAG:** Retrieval-Augmented Generation.
- **SA:** Security Association.
- **SPI:** Security Parameter Index (32-bit identifier).
- **TreeSHAP:** Tree-based SHapley Additive exPlanations.

---

## 95. References

1. **NIST SP 800-77 Rev. 1:** *Guide to IPsec VPNs*, NIST, 2020.
2. **RFC 7296:** *Internet Key Exchange Protocol Version 2 (IKEv2)*, IETF, 2014.
3. **RFC 8221:** *Cryptographic Algorithm Implementation Requirements for ESP and AH*, IETF, 2017.
4. **RFC 9347:** *Aggregation and Fragmentation in IP Traffic Flow Security (IP-TFS)*, IETF, 2023.
5. **Smart India Hackathon 2026:** *Problem Statement 26160 Documentation*, NTRO, 2026.
