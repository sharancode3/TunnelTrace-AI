# TunnelTrace AI — IPsec Security Intelligence Platform

<div align="center">

# TunnelTrace AI
### AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
**Smart India Hackathon 2026 — Problem Statement ID: 26160 (PS 160)**  
**Sponsoring Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity | **Category:** Software

---

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: Specification Baseline Frozen](https://img.shields.io/badge/Status-Specification_Baseline_Frozen-success.svg)](PROJECT_MEMORY.md)
[![Architecture: Local-First Air-Gapped](https://img.shields.io/badge/Architecture-Local--First_Air--Gapped-orange.svg)](docs/architecture/DEPLOYMENT.md)
[![Compliance: NIST SP 800-77 Rev. 1](https://img.shields.io/badge/Compliance-NIST_SP_800--77_Rev._1-red.svg)](docs/architecture/SECURITY_THREAT_MODEL_COMPLIANCE.md)
[![Cryptography: RFC 8221 / RFC 7296](https://img.shields.io/badge/Cryptography-RFC_8221_%2F_RFC_7296-darkgreen.svg)](docs/architecture/TRD.md)
[![Classification: Class A / Class B Privilege Isolation](https://img.shields.io/badge/Security-Class_A%2FB_Privilege_Isolation-purple.svg)](docs/architecture/SYSTEM_ARCHITECTURE.md)
[![Inference: Zero-Decryption Dual Ensemble](https://img.shields.io/badge/ML_Inference-Zero--Decryption_Dual_Ensemble-blueviolet.svg)](docs/architecture/ML_DATASET_ENGINEERING.md)

</div>

---

## Executive Summary

**TunnelTrace AI** is an enterprise-grade, evidence-first **IPsec VPN Protocol Analyzer and Security Assessment Framework** engineered for the **National Technical Research Organisation (NTRO)** under Smart India Hackathon 2026 (Problem Statement ID: `26160`).

Modern national defense organizations, intelligence entities, and critical infrastructure operators rely heavily on IPsec VPNs to establish secure communication enclaves across untrusted or contested wide-area networks. However, real-world deployments face severe operational vulnerabilities:
- **Cryptographic Rot:** Undetected use of deprecated ciphers (3DES, DES, Blowfish), broken hashing algorithms (MD5, SHA-1), and inadequate Diffie-Hellman groups (DH 1, 2, 5) that fail modern NIST standards.
- **Protocol State Desynchronization:** Misconfigured Perfect Forward Secrecy (PFS), asymmetric Security Association (SA) lifetimes, broken Dead Peer Detection (DPD), and silent rekeying failures.
- **Side-Channel Metadata Leakage:** Encapsulated payloads remain opaque, yet packet size dynamics, inter-arrival bursts, and timing signatures expose sensitive inner application behavior (such as VoIP calls, video feeds, and bulk exfiltration) without breaking encryption.
- **Remediation Paralysis:** Network engineers hesitate to update cryptographic policies due to fears of catastrophic tunnel outages on mission-critical links.

**TunnelTrace AI solves this holistically.** It ingests raw packet captures (PCAP/PCAPNG) or live network streams, reconstructs deterministic IKEv1/IKEv2 negotiations and bidirectional Child SA states, infers inner application traffic with **zero payload decryption** using a calibrated dual-ensemble ML pipeline, audits observed postures against versioned Policy-as-Code rules (NIST SP 800-77 Rev. 1 / RFC 8221), simulates safe configuration updates in a **Configuration Security Twin**, and validates automated remediations in an isolated, multi-namespace **strongSwan testbed**.

---

## Master Architecture & Technical Blueprints

### Figure 1: Master System Architecture & Security Boundary Topology (Class A vs. Class B)

The platform enforces strict privilege boundary separation between unprivileged containerized applications (Execution Class A) and host-level networking operations (Execution Class B) communicating across an authenticated UNIX domain socket.

```mermaid
graph TD
    subgraph Client_Tier ["Presentation Tier"]
        UI["Next.js 14 Web Console<br/>(0px Brutalist Interface / React Flow)"]
    end

    subgraph Class_A ["Execution Class A: Unprivileged Container Stack"]
        API["FastAPI Application Server (:8000)<br/>REST /api/v1 and WebSockets"]
        CELERY["Celery Asynchronous Workers<br/>(Parsing, ML Inference, Policy Audit)"]
        REDIS[("Redis 7<br/>Task Queue, Cache and PubSub")]
        POSTGRES[("PostgreSQL 15 + pgvector<br/>State Store and Evidence DAG")]
        STORAGE[("Local Object Storage<br/>(PCAPs, Model Weights, Reports)")]
        LOCAL_LLM["Local LLM Engine<br/>(Ollama / vLLM - Air-Gapped RAG)"]
    end

    subgraph Class_B ["Execution Class B: Privileged Host Network Domain"]
        SOCK{"UNIX Domain Socket RPC<br/>/run/tunneltrace.sock"}
        AGENT["Privileged Network Management Agent"]
        SWAN["strongSwan 5.9+ IPsec Daemon<br/>(ns-peer-a and ns-peer-b Namespaces)"]
        NETEM["Linux tc/netem<br/>Impairment Injection Engine"]
        SNIFF["Raw Socket Packet Sniffer<br/>(Promiscuous libpcap Ring)"]
    end

    UI <-->|"HTTP / WebSocket"| API
    API <-->|"Job Dispatch"| REDIS
    API <-->|"Session Queries"| POSTGRES
    API <-->|"Capture Upload"| STORAGE
    API <-->|"UNIX Socket IPC"| SOCK
    SOCK <-->|"Local RPC"| AGENT

    CELERY <-->|"Consume Tasks"| REDIS
    CELERY <-->|"Persist Evidence DAG"| POSTGRES
    CELERY <-->|"Artifact Storage"| STORAGE
    CELERY <-->|"Local RAG Queries"| LOCAL_LLM

    AGENT <-->|"swanctl / VICI"| SWAN
    AGENT <-->|"Netlink qdisc Rules"| NETEM
    AGENT <-->|"AF_PACKET Stream"| SNIFF
```

---

### Figure 2: End-to-End Forensic Processing & Remediation Pipeline

A four-phase pipeline governing trace ingestion, deterministic protocol extraction, side-channel machine learning, policy evaluation, and closed-loop lab verification.

```mermaid
graph TD
    RAW_CAPTURE["Raw Network Capture: PCAP / Live Stream"] --> INGEST["Capture Ingestion and Header Validator"]
    INGEST --> TSHARK["TShark Subprocess: JSON Event Dissector"]

    TSHARK --> PARSE_IKE["IKE Dissection Module"]
    TSHARK --> PARSE_ESP["ESP Outer Header Dissector"]
    TSHARK --> PARSE_FLOW["Encrypted Flow Side-Channel Extractor"]

    PARSE_IKE --> EXT_VER["Extract IKE Version: IKEv1 vs IKEv2"]
    PARSE_IKE --> EXT_PROP["Extract Transform Proposals: Encr, Integ, PRF, DH"]
    PARSE_IKE --> EXT_SPI["Extract Initiator and Responder SPIs"]

    PARSE_ESP --> EXT_ESP_SPI["Extract ESP Security Parameter Index"]
    PARSE_ESP --> EXT_SEQ["Extract Sequence Numbers and Anti-Replay"]

    PARSE_FLOW --> EXT_TAB["Extract 24 Tabular Features: Lengths, IAT, Bursts"]
    PARSE_FLOW --> EXT_TENS["Construct Directional Sequence Tensors"]

    EXT_VER --> POLICY["Policy-as-Code Engine: NIST SP 800-77 and RFC 8221"]
    EXT_PROP --> POLICY
    EXT_SPI --> POLICY
    EXT_ESP_SPI --> POLICY
    EXT_SEQ --> POLICY

    EXT_TAB --> ML_MODEL["Dual-Ensemble Model: XGBoost + PyTorch 1D-CNN"]
    EXT_TENS --> ML_MODEL

    POLICY --> SCORE["Deterministic 0-100 Security Scoring Engine"]
    ML_MODEL --> CALIB["Platt Temperature Scaling and Entropy OOD Gate"]

    SCORE --> DAG[("Cryptographic Evidence DAG: Frame Byte Provenance")]
    CALIB --> DAG

    DAG --> TWIN["Configuration Security Twin: What-If Simulation"]
    TWIN --> LAB["strongSwan Testbed: ns-peer-a and ns-peer-b Re-Test"]
    LAB -->|"Automated Verification Re-Run"| DAG
    DAG --> REPORT["Cryptographically Signed Defense Audit Report"]
```

---

### Figure 3: Zero-Decryption Encrypted Traffic Machine Learning Engine

Dual-stream feature engineering feeding a parallel model architecture (XGBoost + 1D-CNN) with weighted late fusion, post-hoc Platt temperature scaling, and Shannon entropy out-of-distribution gating.

```mermaid
graph TD
    ESP_FLOW["Encapsulated ESP Flow Stream"] --> SPLIT_FEAT["Dual-Stream Feature Extractor"]

    SPLIT_FEAT --> FEAT_TAB["Tabular Feature Extractor<br/>(24 Statistical Metrics: Lengths, IAT Quantiles, Bursts)"]
    SPLIT_FEAT --> FEAT_SEQ["Sequence Tensor Constructor<br/>(Normalized Direction, Length, Delta-Time Tensors)"]

    FEAT_TAB --> XGB["XGBoost Classifier<br/>(500 Trees, Depth 6, Tabular Dynamics)"]
    FEAT_SEQ --> CNN["PyTorch 1D-CNN<br/>(3 Conv Blocks, BatchNorm, Global MaxPool)"]

    XGB --> FUSION["Weighted Late Fusion Layer<br/>Logits = 0.55 * XGB + 0.45 * CNN"]
    CNN --> FUSION

    FUSION --> PLATT["Platt Temperature Scaling<br/>Calibrated Posterior Probabilities"]
    PLATT --> GATE{"Shannon Entropy Gate<br/>H <= 1.85?"}

    GATE -->|"Pass: Confident"| PREDICTED["Inferred Application Class<br/>(VoIP, Video, Web, SSH, SFTP, Bulk Exfil, DNS)"]
    GATE -->|"Fail: High Uncertainty"| OOD["Quarantined Out-of-Distribution<br/>(Unseen Protocol / Tunnel Evasion Anomaly)"]
```

---

### Figure 4: Configuration Security Twin & Closed-Loop Remediation Cycle

Automated remediation workflow: projecting safe cryptographic migrations in a virtual twin before applying and verifying them in an isolated Linux network namespace testbed.

```mermaid
graph TD
    VULN["Vulnerability Detected: Weak Ciphersuite or Missing PFS"] --> TWIN_INIT["Initialize Configuration Security Twin"]
    TWIN_INIT --> PARSE_CONF["Parse Active strongSwan swanctl.conf Topology"]
    
    PARSE_CONF --> SIMULATE["What-If Simulation Engine<br/>(Compatibility Check, Crypto Overhead and MTU Modeling)"]
    SIMULATE --> PROJECTION["Score Uplift Projection<br/>(Baseline 38/100 -> Target 96/100)"]
    PROJECTION --> PATCH_GEN["Synthesize Remediation Patch<br/>(Unified Diff and Hardened swanctl.conf)"]

    PATCH_GEN --> LAB_PROVISION["Provision strongSwan Testbed<br/>(Linux Namespaces: ns-peer-a and ns-peer-b)"]
    LAB_PROVISION --> NETEM_INJECT["Inject Tactical Impairments<br/>(Linux tc/netem Latency, Jitter, Loss)"]
    NETEM_INJECT --> APPLY_CONFIG["Deploy Synthesized Hardened Configuration"]
    APPLY_CONFIG --> TRAFFIC_RUN["Establish IPsec Tunnel and Stream Synthetic Traffic"]
    TRAFFIC_RUN --> RE_CAPTURE["Capture Verification PCAP and Re-Run Forensics"]

    RE_CAPTURE --> AUDIT_GATE{"Verification Audit Passed?<br/>No Weak Ciphers and Target Score Met"}
    AUDIT_GATE -->|"Yes: Confirmed"| PROD_PATCH["Cryptographically Signed Production Patch"]
    AUDIT_GATE -->|"No: Failed"| ROLLBACK["Automated Rollback and Diagnostic Report"]
```

---

### Figure 5: Architectural Epistemic Separation (Deterministic Forensics vs. Calibrated ML)

Explicit division between facts extracted with 100% certainty from packet headers and application categories inferred probabilistically from encrypted side channels.

```mermaid
graph LR
    subgraph Deterministic_Forensics ["Deterministic Protocol Forensics Layer"]
        D1["IKEv1 / IKEv2 State Machine Tracking"]
        D2["Bidirectional Child SA SPI Pairing"]
        D3["Cryptographic Suite and DH Group Extraction"]
        D4["NIST SP 800-77 Rev. 1 Policy Audit"]
        D5["Byte-Level Frame Offsets and Cryptographic Hashes"]
        DRULE["Epistemic Guarantee:<br/>Protocol parameters are NEVER predicted.<br/>Extracted strictly from wire header bytes."]

        D1 --> D2
        D2 --> D3
        D3 --> D4
        D4 --> D5
        D5 --> DRULE
    end

    subgraph Probabilistic_ML ["Probabilistic Traffic Intelligence Layer"]
        P1["Encrypted ESP Flow Metadata Ingestion"]
        P2["24 Tabular Metrics and Sequence Tensors"]
        P3["Dual-Ensemble Inference: XGBoost + 1D-CNN"]
        P4["Platt Temperature Scaling and Entropy OOD Gating"]
        P5["Inferred Application Category: VoIP, Video, Web"]
        PRULE["Epistemic Guarantee:<br/>Payload data is NEVER decrypted.<br/>Inferred strictly from side-channel metadata."]

        P1 --> P2
        P2 --> P3
        P3 --> P4
        P4 --> P5
        P5 --> PRULE
    end
```

---

## Table of Contents

1. [Core Capabilities & Architectural Pillars](#core-capabilities--architectural-pillars)
2. [Subsystem Capabilities & Technical Specifications](#subsystem-capabilities--technical-specifications)
3. [Competitive Matrix & Value Proposition](#competitive-matrix--value-proposition)
4. [Repository Structure & Specification Suite](#repository-structure--specification-suite)
5. [Technology Stack](#technology-stack)
6. [Quickstart & Local-First Deployment](#quickstart--local-first-deployment)
7. [Golden SIH 2026 Demonstration Flow](#golden-sih-2026-demonstration-flow)
8. [Regulatory Compliance & RFC Standards Matrix](#regulatory-compliance--rfc-standards-matrix)
9. [Security, Privacy & Zero-Egress Governance](#security-privacy--zero-egress-governance)
10. [Problem Statement Attribution](#problem-statement-attribution)
11. [License & Intellectual Property](#license--intellectual-property)

---

## Core Capabilities & Architectural Pillars

| Pillar | Focus Area | Key Technical Mechanisms | Deliverable Outcome |
| :--- | :--- | :--- | :--- |
| **1. Deterministic Protocol Forensics** | IKE & ESP Wire Dissection | TShark / Scapy, state machines, bidirectional SPI tracker | Complete SA session graph & cryptographic inventory |
| **2. Encrypted Traffic Inference** | Side-Channel Metadata Analysis | XGBoost + 1D-CNN, Platt scaling, Shannon entropy OOD gate | Inferred application type with zero payload decryption |
| **3. Policy-as-Code & Scoring** | Regulatory Compliance | Versioned YAML rules, NIST SP 800-77 Rev. 1, RFC 8221 | Mathematical 0–100 score with exact byte citations |
| **4. Configuration Security Twin** | Impact Simulation & Remediation | Headless strongSwan model, Linux network namespaces, tc/netem | Validated configuration patch without production risk |
| **5. Evidence DAG & Local RAG** | Non-Repudiation & Explanation | Merkle-tree rooted DAG, pgvector, local Llama-3 / Mistral-7B | Audit-proof evidence chain & grounded explanation |

---

## Subsystem Capabilities & Technical Specifications

### 1. Deterministic Protocol Forensics & State Reconstruction
- **IKEv1 & IKEv2 State Machines:** Tracks Main Mode, Aggressive Mode, Quick Mode, `IKE_SA_INIT`, `IKE_AUTH`, and `CREATE_CHILD_SA` exchanges with exact message ID sequencing.
- **Cryptographic Transform Extraction:** Dissects every Proposal, Transform, and Attribute structure from SA payloads:
  - Encryption Algorithms (ENCR): AES-GCM, AES-CBC, 3DES, DES, ChaCha20-Poly1305.
  - Integrity Algorithms (INTEG): HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, HMAC-MD5, HMAC-SHA1.
  - Diffie-Hellman Key Exchange Groups (DH): Groups 1, 2, 5, 14, 19, 20, 21, Curve25519.
  - Pseudo-Random Functions (PRF): PRF-HMAC-SHA256, PRF-HMAC-SHA384, PRF-HMAC-MD5.
- **Bidirectional Child SA Pairing:** Binds inbound and outbound Security Parameter Indexes (SPIs) across network endpoints, tracking traffic volume, packet counts, and lifetime expirations.
- **NAT-Traversal & Encapsulation Tracking:** Detects UDP encapsulation on port 4500 (RFC 3948), Non-ESP markers, and keepalive packet streams.

---

### 2. Encrypted Traffic Intelligence (Zero Payload Decryption)
- **Zero Decryption Guarantee:** Adheres to defense data governance mandates. The platform inspects only outer IP/UDP/ESP headers, packet lengths, directionality, and inter-arrival timing dynamics.
- **24 Tabular Side-Channel Features:** Computes burst density, packet size skewness, kurtosis, coefficient of variation, bidirectional volume ratios, and inter-arrival time quantiles.
- **Dual-Ensemble Model:** Combines the gradient-boosted decision tree efficiency of **XGBoost** with the temporal pattern recognition of a **PyTorch 1D-CNN**.
- **Platt Temperature Calibration:** Mitigates uncalibrated neural overconfidence, ensuring displayed confidence scores reflect true empirical accuracy.
- **Shannon Entropy Out-of-Distribution Gating:** Rejects unknown, anomalous, or evasion traffic when prediction entropy exceeds $H = 1.85$, preventing false alarms on unmodeled zero-day protocols.

---

### 3. Policy-as-Code & Audit-Proof Security Scoring
- **Authoritative Cryptographic Standards:** Evaluates captured sessions against strict, machine-readable YAML rules codifying **NIST SP 800-77 Rev. 1**, **RFC 8221**, **RFC 7296**, and **FIPS 140-3**.
- **Deterministic 0–100 Scoring Algorithm:**
  $$S = \max\left(0, 100 - \sum \text{Severity Deductions} + \text{Bonuses}\right)$$
  - **Cryptographic Suite (40%):** Deductions for broken ciphers (3DES: -35), weak DH groups (DH 2: -25), deprecated hashes (SHA-1: -20).
  - **Protocol Hygiene & Key Exchange (25%):** Penalties for disabled PFS (-15), aggressive mode usage (-20), missing DPD (-10).
  - **Identity & Authentication (20%):** Auditing PSK entropy and X.509 certificate trust chains.
  - **Operational Posture (15%):** SA lifetime configuration and rekeying grace period audits.
- **Zero-Hallucination Assurance:** All deductions are derived deterministically from YAML policy definitions and linked to exact packet frame numbers.

---

### 4. The Configuration Security Twin
- **Headless Virtual Clone:** Ingests active strongSwan (`ipsec.conf` / `swanctl.conf`) configurations and models them in a virtual state machine.
- **What-If Impact Simulator:** Projects the consequence of ciphersuite upgrades prior to touching production hardware:
  - Validates compatibility against remote peer capabilities.
  - Calculates cryptographic computational overhead and throughput impact.
  - Detects potential Path MTU (PMTU) and ESP fragmentation hazards.
- **Score Uplift Projection:** Accurately predicts the post-remediation security score (for example, demonstrating a verified leap from 38/100 to 96/100).

---

### 5. Automated strongSwan Remediation Testbed
- **Multi-Namespace Virtual Lab:** Provisions fully isolated Linux network namespaces (`ns-peer-a` $\leftrightarrow$ `ns-peer-b`) interconnected via `veth` pairs without requiring physical router hardware.
- **Network Impairment Simulation:** Employs Linux `tc` / `netem` to inject real-world tactical network conditions:
  - Variable latency (10ms – 500ms) and packet jitter ($\pm 30\text{ms}$).
  - Configurable packet loss (0.1% – 15%) and out-of-order packet delivery.
- **Automated Verification Loop:** Deploys synthesized remediation configurations, establishes live IPsec tunnels, injects synthetic test workloads, records fresh PCAP traces, and re-evaluates compliance in a fully closed loop.

---

### 6. Byte-Level Cryptographic Evidence DAG
- **Immutable Provenance:** Every finding, deduction, and compliance check is anchored in a Directed Acyclic Graph (DAG) persisted in PostgreSQL.
- **Wire-Level Precision:** Points directly to the packet number, timestamp, protocol layer, field name, and hexadecimal byte offset (for example, `Frame 14, Offset 0x0042: Transform Type 1 = ENCR_3DES`).
- **Cryptographic Integrity:** Each evidence record includes a SHA-256 hash of the parent PCAP segment, guaranteeing non-repudiation in intelligence and court-admissible forensic scenarios.

---

### 7. Air-Gapped Grounded AI Analyst (Local RAG)
- **100% Offline & Sovereign:** Powered by local open-weight language models (such as Llama-3-8B-Instruct or Mistral-7B via Ollama / vLLM). No data ever leaves the local enclave.
- **Grounded Retrieval-Augmented Generation:** Queries a vector database (`pgvector`) populated with RFC 7296, RFC 8221, RFC 4301, NIST SP 800-77 Rev. 1, and the current session's Evidence DAG nodes.
- **Strict Guardrails:** The AI Analyst is constrained by strict system prompts: it cannot invent vulnerabilities, override deterministic scores, or assert findings without citing frame numbers and RFC section numbers.

---

## Competitive Matrix & Value Proposition

| Evaluation Vector | Traditional Packet Sniffers (Wireshark / tcpdump) | Generic Cloud SIEMs (Splunk / QRadar) | Black-Box AI Anomaly Detectors | TunnelTrace AI (SIH 2026 / NTRO) |
| :--- | :--- | :--- | :--- | :--- |
| **IKE/ESP State Reconstruction** | Manual packet dissection; no automated session graph | Log-based only; blind to wire-level protocol state | Opaque embeddings; cannot reconstruct SA states | **Automated, deterministic IKEv1/IKEv2 & ESP state machines** |
| **Encrypted Flow Visibility** | Blind beyond ESP header (requires private keys) | None; relies on host endpoint agents | Uncalibrated anomaly scores; high false-positive rate | **Dual-ensemble ML (XGBoost + 1D-CNN) with zero decryption** |
| **Out-of-Distribution Detection** | Not applicable | Rule-based threshold alerts | Fails silently on unseen zero-day traffic | **Shannon entropy gating + Platt temperature scaling** |
| **Regulatory Compliance** | Manual inspection against printed standards | Generic CIS/ISO compliance templates | No compliance mapping | **Native NIST SP 800-77 Rev. 1 & RFC 8221 Policy-as-Code** |
| **Evidence Provenance** | Individual frame numbers | Aggregated log indices | None (black-box latent vector) | **Cryptographic Evidence DAG linked to raw byte offsets** |
| **Remediation Safety** | Manual CLI editing on live routers | Script push without validation | Automated actions risk breaking live tunnels | **What-if Configuration Twin + Closed-Loop Lab Re-test** |
| **Deployment Model** | Desktop utility | Heavy cloud infrastructure | Proprietary cloud SaaS | **100% Local-First, air-gapped Docker container stack** |

---

## Repository Structure & Specification Suite

The repository is structured into an approved, industry-grade specification and implementation hierarchy:

```
TunnelTrace-AI/
├── .github/                       # CI/CD Workflows & GitHub Actions
├── docs/                          # Master Technical Specification Suite
│   ├── README.md                  # Comprehensive Documentation Index
│   ├── requirements/              # Requirements & Acceptance Specifications
│   │   ├── PRD.md                 # Product Requirements Document (60 sections)
│   │   ├── RTM.md                 # Requirements Traceability Matrix (55 PS clauses)
│   │   ├── TESTING_VALIDATION_PLAN.md # V&V Test Plan (L1–L10, 34 test matrices)
│   │   └── USER_GUIDE_AND_DEMO_RUNBOOK.md # Operator Guide & 12-Step SIH Runbook
│   └── architecture/              # Architecture & System Design Specifications
│       ├── SYSTEM_ARCHITECTURE.md # System Architecture & Design (SAD)
│       ├── TRD.md                 # Technical Requirements & Design (TDD)
│       ├── WORKFLOW.md            # End-to-End Workflow & Data Flow (DFD L0–L2)
│       ├── DATABASE_DESIGN.md     # Relational Schemas, pgvector & Evidence DAG
│       ├── ML_DATASET_ENGINEERING.md # Dataset Generation, Models & Calibration
│       ├── SECURITY_THREAT_MODEL_COMPLIANCE.md # STRIDE, Scope A/B & Policy-as-Code
│       ├── API_INTEGRATION_SPECIFICATION.md # REST /api/v1, WebSockets & Socket RPC
│       ├── UI_UX_DESIGN_SYSTEM.md # 0px Brutalist Design System & 18 Wireframes
│       └── DEPLOYMENT.md          # Docker Stack, Class A/B Isolation & Runbooks
├── backend/                       # FastAPI Server & Celery Pipeline (Phase 1)
│   ├── app/                       # Application Core, Routers & Models
│   ├── tests/                     # Unit, Integration & Fuzzing Tests
│   └── alembic/                   # PostgreSQL Migration Scripts
├── frontend/                      # Next.js 14 Web Application (Phase 2)
│   ├── src/                       # Components, Pages, Stores & Visualizers
│   └── public/                    # Static Assets & Icons
├── lab/                           # strongSwan Testbed & Privileged Agent
│   ├── agent/                     # Class B Privileged Network Daemon
│   ├── scripts/                   # Namespace Creation & tc/netem Configs
│   └── configs/                   # Vulnerable & Hardened strongSwan Profiles
├── policies/                      # Policy-as-Code Definitions (YAML)
│   ├── nist_sp_800_77_r1.yaml     # Authoritative NIST Cryptographic Rules
│   └── rfc_8221_ciphers.yaml      # RFC Cryptographic Suite Requirements
├── docker-compose.yml             # Local-First Multi-Container Deployment Stack
├── PROJECT_MEMORY.md              # Living Master Memory & Technical Decision Log
└── README.md                      # Primary Repository Overview & Architecture Guide
```

---

## Technology Stack

| Architecture Layer | Technology Selection | Exact Version | Rationale & Responsibility |
| :--- | :--- | :--- | :--- |
| **Presentation Tier** | Next.js / TypeScript | `14.2+` / `5.4+` | High-performance React framework, Server-Side Rendering, typed contracts |
| **Styling & UI System** | Tailwind CSS / Lucide | `3.4+` | 0px sharp brutalist design tokens, high-density tactical SOC layout |
| **Topology Visualizer** | React Flow / Dagre | `11.11+` | Interactive IKE/ESP Security Association state graphs and Evidence DAG |
| **Backend API Gateway** | FastAPI (Python) | `0.110+` | Asynchronous ASGI gateway, OpenAPI autogeneration, Pydantic v2 validation |
| **Data Serialization** | Pydantic | `v2.6+` | Contract-first DTO schemas, strict validation, zero-copy serialization |
| **Task Queue & Broker** | Celery / Redis | `5.3+` / `7.2+` | Distributed task execution for heavy PCAP parsing, ML inference, and reports |
| **Relational Database** | PostgreSQL | `15.6+` | Acid-compliant state store, temporal session indexing, relational integrity |
| **Vector Search Engine** | pgvector extension | `0.6+` | High-dimensional embedding storage for RFC documents and RAG queries |
| **Protocol Forensics** | TShark / PyShark / Scapy | `4.2+` / `0.6+` | Low-level C-based wire dissection, frame offset extraction, packet parsing |
| **ML: Gradient Boosting** | XGBoost | `2.0+` | High-speed inference over 24 tabular statistical side-channel features |
| **ML: Deep Learning** | PyTorch | `2.2+` | 1D-CNN temporal sequence modeling over packet length and timing tensors |
| **Explainable AI (XAI)** | TreeSHAP | `0.44+` | Local feature attribution explaining why an encrypted flow was classified |
| **Local LLM Runtime** | Ollama / vLLM | `0.1.30+` | 100% offline, air-gapped natural language inference (Llama-3-8B / Mistral-7B) |
| **VPN Testbed Daemon** | strongSwan | `5.9.13+` | Standard-compliant IKEv1/IKEv2 daemon supporting custom crypto suites |
| **Traffic Emulation** | Linux iproute2 / tc | Kernel 5.15+ | Multi-namespace routing (veth), latency, jitter, and loss injection |
| **Report Generation** | WeasyPrint / Jinja2 | `61.0+` | Cryptographically signed, audit-grade executive and technical PDF reports |

---

## Quickstart & Local-First Deployment

TunnelTrace AI is designed to run 100% locally on standard x86_64 Linux workstations without requiring external cloud accounts or internet connectivity.

### System Prerequisites
- **Operating System:** Linux (Ubuntu 22.04 LTS recommended) or Windows 11 with WSL2 (Ubuntu 22.04).
- **CPU & RAM:** Minimum 4 Cores, 8 GB RAM (16 GB recommended for local LLM inference).
- **Docker Engine:** Docker 24.0+ and Docker Compose v2.20+.
- **Kernel Requirements (For Lab Testbed):** Linux Kernel 5.15+ with `CONFIG_NET_SCHED` and network namespace support.

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/sharancode3/TunnelTrace-AI.git
cd TunnelTrace-AI
```

### Step 2: Configure Environment Variables
```bash
cp .env.example .env
# Default environment is pre-configured for 100% local, air-gapped operation
```

### Step 3: Launch Local Core Stack (Execution Class A)
```bash
docker compose up -d
```
*This initializes PostgreSQL 15 with pgvector, Redis 7, the FastAPI backend server, Celery asynchronous workers, and the Next.js frontend console.*

### Step 4: Verify Subsystem Health
```bash
# Verify all containers are healthy
docker compose ps

# Check API health endpoint
curl -s http://localhost:8000/api/v1/health | jq .
```
Expected output:
```json
{
  "status": "HEALTHY",
  "version": "0.1.0-alpha",
  "database": "CONNECTED",
  "redis": "CONNECTED",
  "worker_pool": "ACTIVE",
  "privileged_agent": "CONNECTED"
}
```

### Step 5: (Optional) Initialize Privileged Testbed (Execution Class B)
*Requires root / sudo privileges on the host Linux system to establish network namespaces:*
```bash
sudo ./lab/scripts/setup_testbed.sh
sudo systemctl start tunneltrace-agent
```

### Step 6: Access the Web Console
Open your browser and navigate to:
```
http://localhost:3000
```
- **Dashboard:** High-level security posture, active captures, and score trends.
- **PCAP Forensics:** Drag-and-drop `.pcap` files for instantaneous dissection.
- **SA Visualizer:** Interactive state graph of IKE/ESP Security Associations.
- **Configuration Twin:** Side-by-side what-if simulation and strongSwan patch diffs.
- **Remediation Lab:** Trigger automated multi-namespace re-testing.

---

## Golden SIH 2026 Demonstration Flow

The following 12-step sequence constitutes the primary evaluation walkthrough designed for NTRO judges during the Smart India Hackathon 2026 Grand Finale:

| Step | Action | Execution Details | Expected Evaluation Output |
| :---: | :--- | :--- | :--- |
| **01** | **Cold Start Verification** | Launch platform via `docker compose up -d` | All containers green; zero external network egress |
| **02** | **Weak Capture Ingestion** | Upload `sample_weak_3des_dh2.pcap` | Ingestion complete in < 2.5s; SHA-256 hash locked |
| **03** | **Deterministic Forensics** | TShark extracts IKEv1 Main Mode & Child SAs | Bidirectional SPIs paired; 3DES-CBC and DH2 isolated |
| **04** | **Policy Compliance Audit** | Policy engine evaluates NIST SP 800-77 rules | Critical Violations: `VULN-001` (3DES), `VULN-002` (DH2) |
| **05** | **Security Scoring** | Algorithm computes baseline score | **Security Score: 38/100 (CRITICAL NON-COMPLIANCE)** |
| **06** | **Encrypted Flow ML** | XGBoost + 1D-CNN classify encapsulated traffic | Inferred inner flow: **VoIP (94.2% conf)** with zero decryption |
| **07** | **Evidence DAG Inspection** | Drill into finding in the Web Console | UI highlights Frame 4, Offset `0x003A` showing Transform 3DES |
| **08** | **What-If Twin Simulation** | Launch Configuration Security Twin | Proposes AES-256-GCM + DH19 + PFS; projects **Score: 96/100** |
| **09** | **Automated Patch Synthesis** | Click "Generate Hardened Patch" | Produces clean, unified diff for `swanctl.conf` |
| **10** | **Testbed Closed-Loop Test** | Click "Verify in Lab Testbed" | Agent updates `ns-peer-a`, establishes tunnel, streams packets |
| **11** | **Delta Score Verification** | System captures fresh verification PCAP | Automated re-audit confirms **Score: 96/100 (VERIFIED)** |
| **12** | **Executive Report Export** | Click "Export Signed Defense Report" | Generates tamper-proof PDF with complete cryptographic chain |

---

## Regulatory Compliance & RFC Standards Matrix

TunnelTrace AI natively implements and verifies compliance against the following official standards:

| Standard / RFC | Document Title | TunnelTrace AI Implementation Scope |
| :--- | :--- | :--- |
| **NIST SP 800-77 Rev. 1** | *Guide to IPsec VPNs* | Authoritative ruleset for cipher suites, hash functions, and DH key sizes |
| **RFC 8221** | *Cryptographic Algorithm Implementation Requirements for ESP/AH* | Categorization of MUST, SHOULD, and MUST NOT cryptographic algorithms |
| **RFC 7296** | *Internet Key Exchange Protocol Version 2 (IKEv2)* | Full state machine tracking, exchange parsing, and notification dissection |
| **RFC 4301** | *Security Architecture for the Internet Protocol* | Security Association (SA) and Security Policy Database (SPD) modeling |
| **RFC 4303** | *IP Encapsulating Security Payload (ESP)* | ESP header parsing, sequence counter tracking, and anti-replay verification |
| **RFC 3948** | *UDP Encapsulation of IPsec ESP Packets* | NAT-Traversal (NAT-T) port 4500 detection and SPI preservation |
| **FIPS 140-3** | *Security Requirements for Cryptographic Modules* | Validation of approved cryptographic primitives and key derivation |
| **NSA CNSA Suite** | *Commercial National Security Algorithm Suite* | Quantum-resistant cryptographic migration recommendations (AES-256 / DH 19/21) |

---

## Security, Privacy & Zero-Egress Governance

### Execution Class Isolation
- **Execution Class A (Unprivileged):** The Web Console, FastAPI Gateway, Celery Workers, Redis, and PostgreSQL run as unprivileged, unmapped service accounts within isolated Docker containers. They have zero access to raw host sockets.
- **Execution Class B (Privileged Agent):** The privileged strongSwan daemon and packet capture engine run exclusively within a dedicated host-level daemon communicating with Class A exclusively over an authenticated, permission-restricted **UNIX Domain Socket** (`/run/tunneltrace.sock`).

### Zero Payload Decryption
TunnelTrace AI does **not** perform Man-in-the-Middle (MitM) TLS/ESP termination, does **not** solicit private cryptographic keys from administrators, and does **not** reconstruct plaintext application payloads. All application traffic intelligence is derived exclusively from side-channel statistical metadata (packet sizes, timing, bursts).

### Air-Gapped / Zero Data Egress
The entire platform operates 100% offline. No telemetry, crash reports, packet fragments, or embeddings are ever transmitted outside the host machine. The integrated RAG AI Analyst operates against locally hosted language models running in memory.

---

## Problem Statement Attribution

- **Competition:** Smart India Hackathon (SIH) 2026, Grand Finale
- **Problem Statement ID:** `26160` (Internal Reference: PS 160)
- **Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
- **Sponsoring Agency:** **National Technical Research Organisation (NTRO)**
- **Theme:** Blockchain & Cybersecurity
- **Category:** Software
- **Target Users:** Defense SOC Analysts, Intelligence Protocol Engineers, Military Communications Auditors, Critical Infrastructure Network Operators

---

## License & Intellectual Property

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for complete terms.

```
Copyright 2026 TunnelTrace AI Contributors (SIH 2026 Team)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
