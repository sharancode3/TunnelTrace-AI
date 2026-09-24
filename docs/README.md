# TunnelTrace AI — Technical Documentation Index
## Smart India Hackathon 2026 | Problem Statement 26160 (PS 160)
### Sponsoring Agency: National Technical Research Organisation (NTRO) | Theme: Blockchain & Cybersecurity

---

This directory contains the complete, industry-grade technical specification and operational documentation suite for **TunnelTrace AI** (IPsec Security Intelligence Platform).

The documentation is organized into two primary categories:
1. **[Requirements & Acceptance (`docs/requirements/`)](#1-requirements--acceptance-documentation)** — Functional requirements, traceability, verification planning, and operational analyst/demo runbooks.
2. **[Architecture & Design (`docs/architecture/`)](#2-architecture--design-documentation)** — Systems, technical algorithms, data modeling, ML pipelines, security threat models, API contracts, UI design system, and deployment architecture.

---

## 1. Requirements & Acceptance Documentation (`docs/requirements/`)

| Document | File Link | Purpose & Scope |
| :--- | :--- | :--- |
| **Product Requirements Document (PRD)** | [`docs/requirements/PRD.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/requirements/PRD.md) | 60 Sections: Functional and non-functional requirements (`LAB-`, `CAP-`, `PROTO-`, `SA-`, `FLOW-`, `ML-`, `SEC-`, `REM-`). |
| **Requirements Traceability Matrix (RTM)** | [`docs/requirements/RTM.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/requirements/RTM.md) | 37 Sections: 25-column matrix mapping all 55 NTRO PS requirements to components, tests, and demo proofs. |
| **Testing, Validation & Evaluation Plan** | [`docs/requirements/TESTING_VALIDATION_PLAN.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/requirements/TESTING_VALIDATION_PLAN.md) | 99 Sections: 34 test matrices, V&V levels L1–L10, 31-step Golden Acceptance Flow, and zero-hallucination verification rules. |
| **User / Analyst Guide + Demo Runbook** | [`docs/requirements/USER_GUIDE_AND_DEMO_RUNBOOK.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/requirements/USER_GUIDE_AND_DEMO_RUNBOOK.md) | 96 Sections: Complete analyst user manual, evidence interpretation, 12-step SIH Demo Runbook, and 3-tier fallback matrix. |
| **Expert-Revised Implementation Roadmap** | [`docs/requirements/EXPERT_REVISED_IMPLEMENTATION_ROADMAP.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/requirements/EXPERT_REVISED_IMPLEMENTATION_ROADMAP.md) | As-built audit gate plus bounded tool integrations, monitoring, drift, risk context, ML validation, replay, remediation, SOC UX, and release acceptance. |

---

## 2. Architecture & Design Documentation (`docs/architecture/`)

| Document | File Link | Purpose & Scope |
| :--- | :--- | :--- |
| **System Architecture & Design (SAD)** | [`docs/architecture/SYSTEM_ARCHITECTURE.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/SYSTEM_ARCHITECTURE.md) | 77 Sections: 19 Mermaid diagrams, Three Domains, Class A (unprivileged) vs. Class B (privileged) boundaries. |
| **Technical Requirements & Design (TRD/TDD)** | [`docs/architecture/TRD.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/TRD.md) | 87 Sections: Mathematical formulations, transform lookups, subsystem algorithms, and data schemas. |
| **End-to-End Workflow & Data Flow** | [`docs/architecture/WORKFLOW.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/WORKFLOW.md) | 80 Sections: DFD Level 0/1/2, state machines, and the 31-step Golden SIH Demonstration Workflow. |
| **Data Architecture & Database Design** | [`docs/architecture/DATABASE_DESIGN.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/DATABASE_DESIGN.md) | 85 Sections: PostgreSQL 15 + `pgvector`, 38-table dictionary, foreign key maps, and Evidence DAG. |
| **ML & Dataset Engineering** | [`docs/architecture/ML_DATASET_ENGINEERING.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/ML_DATASET_ENGINEERING.md) | 99 Sections: Native strongSwan dataset factory, `GroupKFold` on `session_id`, XGBoost + 1D-CNN dual ensemble, OOD. |
| **Security, Threat Model & Compliance** | [`docs/architecture/SECURITY_THREAT_MODEL_COMPLIANCE.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/SECURITY_THREAT_MODEL_COMPLIANCE.md) | 109 Sections: Scope A & B, YAML Policy-as-Code, STRIDE, 10 Abuse Cases, and zero-hallucination rules. |
| **API & Integration Specification** | [`docs/architecture/API_INTEGRATION_SPECIFICATION.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/API_INTEGRATION_SPECIFICATION.md) | 95 Sections: REST `/api/v1` routes, WebSockets, async job contracts, Pydantic DTOs, and socket RPC. |
| **UI/UX & Design System Document** | [`docs/architecture/UI_UX_DESIGN_SYSTEM.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/UI_UX_DESIGN_SYSTEM.md) | 74 Sections: 0px brutalist SOC console, Light default (`#F7F7F4`), Dark secondary, and 18 ASCII wireframes. |
| **Deployment, DevOps & Operations** | [`docs/architecture/DEPLOYMENT.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/docs/architecture/DEPLOYMENT.md) | 97 Sections: Local-first Docker Compose, Class A/B isolation, 17 runbooks, and Supabase/Vercel paths. |

---

## 3. Authoritative Operational Memory

- **Master Project Memory:** [`PROJECT_MEMORY.md`](file:///c:/SHARAN%20PROJECTS/TunnelTrace%20AI/PROJECT_MEMORY.md) (Located at repository root) — The living single source of truth tracking frozen architectural decisions, progress, and verification status.
