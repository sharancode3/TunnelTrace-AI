# TunnelTrace AI Expert Revised Implementation Roadmap

**Purpose:** Update the implementation plan using the two expert documents, the current repository, and verified vendor documentation. This roadmap preserves the work already present and defines the next engineering increments; it does not authorize broad network scans or production VPN changes.

**Planning rule:** Stages 1–12 remain the project’s existing implementation history. Their completion labels are not accepted as proof by themselves. Start with Stage 0, reconcile actual code and runtime evidence, repair demonstrable gaps, then implement the additions in order. Do not rebuild completed subsystems just to rename them.

## 1. Recommendation

Evolve TunnelTrace from a PCAP-centered analyzer into an evidence-driven IPsec assurance and monitoring platform. Integrate the named tools as bounded sources or lab instruments; do not make each tool a separate authority. Keep one canonical evidence model and one deterministic policy engine. Add continuous monitoring, deployment drift, implementation-vulnerability context, stronger operational risk views, reproducible replay, and empirical ML robustness only where evidence can support them.

The six proposed tools have different roles:

| Tool | Appropriate TunnelTrace role | Important limit and control |
|---|---|---|
| Wireshark / TShark | TShark remains the machine parser already used by the backend. Wireshark is an analyst review and parser-differential tool, and its version and dissector fields belong in provenance. | It dissects packets; it does not establish the complete deployed security posture. Do not create a second product parser whose facts disagree with the normalized TShark evidence. |
| strongSwan | Continue as the controlled interoperability, scenario-generation, and remediation-verification endpoint. Record the actual binary, build options, plugins, kernel, and configuration used by each run. | Pin and validate versions instead of copying a version claim into a manifest. The current repository’s records disagree between 5.9.8 and 6.0.4. Vendor documentation currently lists 6.1.0 and says IKEv1 is disabled by default there, so upgrades need explicit IKEv1 and plugin compatibility tests. |
| ike-scan | Optional, explicitly authorized IKE endpoint discovery and bounded proposal enumeration. Store target scope, scan profile, tool version, timestamps, raw output hash, and normalized observations. | Its upstream project describes Phase 1 Main/Aggressive Mode probing and transform enumeration; this is not a general IKEv2 vulnerability scanner. Exclude PSK cracking, username enumeration, and unbounded probing from the product workflow. |
| Nmap | Optional authorized host/port/service inventory around a VPN endpoint, including IKE/NAT-T and management-plane exposure. Import normalized XML output or execute a narrow allowlisted scan profile. | Nmap output is discovery evidence, not proof of a vulnerable service or a secure/unsafe VPN. UDP results may be open or filtered/ambiguous. Require explicit target CIDRs, ports, time window, rate limit, exclusions, and operator identity. |
| Scapy | Lab-only packet construction, controlled mutation, regression fixtures, and adversarial traffic transformations in TunnelTrace-owned namespaces. | It can send arbitrary packets and may need network privileges. Never expose a general packet-send or Python execution API; provide typed, bounded lab scenarios and enforce the Class A/Class B boundary. |
| Greenbone / OpenVAS | Optional external vulnerability assessment connector. Import a completed report with scanner/feed version, scan configuration, target scope, timestamp, and report digest. | It is a separate vulnerability-management stack with scanner services and synchronized feeds. Treat findings as supporting evidence with coverage and freshness, not an IPsec protocol oracle or guaranteed-complete inventory. Do not bundle it into the core runtime by default. |

Wireshark and TShark share dissectors and filters, so the useful improvement is parser-version governance and differential validation, not duplicating the forensic engine. [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/), [TShark/Wireshark filter reference](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)

## 2. Revised delivery stages

### Stage 0 — As-built audit and truth reconciliation

**Purpose:** Establish what actually works before adding features.

**Work:**

- Inventory the existing Stage 1–12 code, migrations, API routes, fixtures, model artifacts, policy files, browser routes, and test evidence. Record implementation state separately from validation state.
- Resolve contradictory project memory sections and stale release claims. Generate version, model, embedding, policy, fixture, and source-control fields from inspected runtime/build inputs rather than literals.
- Trace one real capture through upload, immutable storage/hash, TShark observations, reconstruction, persisted flow features, ML prediction persistence, deterministic policy, evidence graph, report, and frontend. Use the same analysis ID and capture hash across every step.
- Static inspection found an ML integration gap to validate: the analysis worker calls protocol dissection, reconstruction, and security assessment, while the traffic API reads `FlowClassification` rows; repository search found the inference service definition but no application call that creates those rows. Prove the current call path and wire it into the analysis lifecycle if missing.
- Remove numeric or success-shaped UI fallbacks when no authoritative result exists. The current remediation page renders `45.0` and `+52.0` when the API provides no twin; the placeholder route also presents a completed pipeline. Render `UNKNOWN`, “not run,” or a clear empty/error state instead.
- Replace universal “zero hallucination” wording with bounded claims about grounding, citation validation, fact locking, and abstention.
- Validate schema/migration head from Alembic itself, not filename sorting; make health/RTM checks fail when core checks are skipped or evidence is absent.

**Exit evidence:** One traceable baseline report with reproducible commands/logs, actual versions and hashes, explicit blockers, and a verified end-to-end result or a precise failure boundary. No stage is called validated solely because source files or tests exist.

### Stage 13 — Safe assessment-tool adapters and scope control

**Purpose:** Incorporate external scanner evidence without giving tools authority over findings or uncontrolled access to targets.

**Work:**

- Define a versioned `AssessmentJob` contract: engagement ID, operator, approved target CIDRs/hostnames, permitted ports, scan profile, start/end window, rate/concurrency caps, excluded assets, authorization reference, and cancellation state.
- Build typed adapters for Nmap and ike-scan with argument arrays, `shell=False`, fixed templates, timeouts, output-size limits, redacted logs, explicit binary/version detection, and raw-output digests. Reject arbitrary command strings and out-of-scope targets before launch.
- Prefer report import for Greenbone in the first increment. Normalize host, service, product/version claim, finding, CVE/CPE, scanner/feed versions, timestamps, evidence, and coverage. Mark missing or stale feed/scan coverage as unknown, not clean.
- Use Wireshark/TShark differential checks against known captures to catch parser-field/version changes. TShark remains the production observation source until a reviewed versioned adapter intentionally changes it.
- Route Scapy only through lab scenario IDs and typed mutation parameters. Run it inside isolated TunnelTrace-owned namespaces with hard packet/rate/time bounds.
- Create a scanner evidence state that distinguishes `OBSERVED`, `INFERRED`, `UNKNOWN`, `STALE`, `OUT_OF_SCOPE`, and `NOT_RUN` from deterministic policy outcomes.

**Exit evidence:** Safe-scope tests, canned output fixtures, parser/version compatibility records, cancellation/resource-limit proofs, and zero execution for malformed or unauthorized jobs.

### Stage 14 — Continuous IPsec sensor and event pipeline

**Purpose:** Add an optional monitoring mode without weakening offline forensics or local-first operation.

**Work:**

- Keep packet capture in the small privileged sensor/agent. The normal API, Celery, ML, and UI services remain unprivileged. Use allowlisted interfaces, capture filters, bounded ring buffers/spooling, backpressure, loss counters, and explicit retention controls.
- Define durable capture sessions and ordered event envelopes with sensor ID, asset/tunnel identity, event time and ingest time, sequence/watermark, source type, parser version, deduplication key, and evidence references.
- Derive observable events for IKE SA/Child SA creation/deletion/rekey, SPI rollover, observed peer changes, proposal changes/downgrades, retransmission patterns, and capture gaps. Obtain tunnel-up/down, DPD timeout, authentication failure, and daemon/plugin events from authorized endpoint logs/telemetry when packet-only observation cannot prove them.
- Implement idempotent event processing, reconnect/replay, duplicate suppression, gap detection, clock-skew handling, queue-full behavior, and durable state recovery.
- Add alert rules with severity rationale, evidence links, suppression/deduplication windows, acknowledgement, and audit trail. A missing packet is not automatically proof of a failed tunnel.

**Exit evidence:** Long-running soak and restart tests, known-loss scenarios, event ordering/dedup tests, capture-overrun visibility, and sensor-down behavior that leaves offline analysis usable.

### Stage 15 — Canonical VPN inventory, configuration drift, and certificate intelligence

**Purpose:** Compare observed tunnel behavior with explicitly supplied or collected expected configuration.

**Work:**

- Define a vendor-neutral VPN configuration IR for IKE version, authentication mode, identities, proposals, PRF/integrity, DH/KE, PFS, traffic selectors, lifetimes, DPD, NAT-T, MTU, certificate references, and implementation/plugin inventory.
- Add import adapters incrementally, beginning with strongSwan. Add one additional vendor only after real configuration fixtures, parser coverage, and semantics are agreed; do not claim multi-vendor support from an abstract schema alone.
- Store approved baseline snapshots immutably and compare them with configuration/runtime inventory and independently observed wire state. Each field carries source, timestamp, confidence/evidence state, and provenance. Report drift as a diff; do not fill missing fields by guessing.
- Build certificate checks from authorized certificate/configuration inventory: validity dates, signature/key strength, trust chain, SAN/identity match, issuer changes, expiry windows, and rotation/reuse relationships.
- Do not claim passive PCAP can reveal certificate details hidden inside encrypted IKE_AUTH exchanges. If no authorized config, endpoint telemetry, or certificate artifact is available, certificate posture is `UNKNOWN`.

**Exit evidence:** StrongSwan fixtures plus redacted vendor fixtures, round-trip/semantic-diff validation, drift tests for each field, and explicit UNKNOWN tests for passive-only evidence.

### Stage 16 — Risk profile, implementation-vulnerability context, and policy lifecycle

**Purpose:** Make risk multidimensional and contextual rather than reducing the product to one opaque score.

**Work:**

- Keep the current 0–100 score as a secondary, versioned product summary. Make the primary view a risk vector with separate evidence-backed dimensions: cryptographic posture, authentication/identity, protocol hygiene, exposure, implementation vulnerability, availability/operations, configuration drift, traffic anomaly, compliance, and evidence confidence/coverage.
- Keep `PASS`, `FAIL`, `UNKNOWN`, and `NOT_APPLICABLE` semantics. Unknown evidence carries a coverage/uncertainty indicator and does not silently become a failure or a low-risk result.
- Add implementation CVE correlation only when product, vendor, exact version/build, platform/package provenance, and affected-version range are known. Track advisory source, retrieval time, applicability logic, fix version, and confidence. Do not treat a banner/version guess as proof of vulnerability.
- Use NVD CPE/CVE data and vendor advisories as versioned sources; retain source snapshots or identifiers so offline results can be reproduced. The NVD itself describes CPE matching as an applicability process and notes that CPE data may be incomplete, so unmatched products remain unknown.
- Map ATT&CK only when a specific observed behavior supports a technique mapping. Pin a MITRE ATT&CK STIX/TAXII dataset version and preserve the mapping rationale and evidence. Configuration weakness alone must not be presented as attacker behavior.
- Version and hash every policy bundle. Implement policy diff and “evaluate this historical capture under policy version A vs B,” preserving the original result and making reevaluation a new run.
- Threat-intelligence correlations are optional, locally cacheable, freshness-bound supporting evidence. An IP/domain reputation match is not proof that a peer is malicious.

**Exit evidence:** Synthetic and real fixture tests for exact-vs-ambiguous version matches, policy history and diff, ATT&CK mappings, stale intelligence, score/vector consistency, and report reproduction.

### Stage 17 — ML integration, empirical benchmark, and adversarial robustness

**Purpose:** Prove the existing ML branch is actually part of analysis and measure where it generalizes.

**Work:**

- Integrate `Stage7InferenceService` into the real analysis worker after ESP flow reconstruction. Persist model version/hash, feature-schema version/hash, per-flow features or governed references, calibrated class probabilities, predicted class, OOD decision, anomaly output, degradation reason, and SHAP attributions transactionally or with clear partial-state semantics.
- Make the UI read persisted results from the same analysis run. If artifacts/model are absent or incompatible, return `UNKNOWN`/degraded with a reason; never fabricate predictions or mark ML complete.
- Separate known-class traffic inference, open-set/OOD rejection, per-flow behavioral anomaly, and tunnel/peer temporal baseline deviation. Isolation Forest output is not attack detection. Add a time-window baseline only when sufficient comparable observations exist and show its warm-up/coverage state.
- Publish a reproducible benchmark card and machine-readable run manifest. Report per-class precision/recall/F1, macro and weighted F1, confusion matrix, OOD AUROC/AUPR and false-accept/false-reject rates, calibration (Brier score and a defined ECE method), robustness degradation, latency/throughput, memory, and coverage. Include session-grouped isolation and cross-environment/vendor splits; keep all thresholds empirical.
- Build controlled transformations for packet-size distributions, timing, burst shape, padding, segmentation/aggregation, loss, and shaping in the lab. Measure prediction shift, abstention, false positives/negatives, and class-wise degradation. Do not train/test on packet-level siblings or use the test set to tune thresholds.
- Expose top contributing features and their direction/units, model uncertainty, OOD status, sample sufficiency, and degraded state in the UI. Label SHAP as feature attribution, not causality.

**Exit evidence:** Re-runnable data/model/metric bundle, leakage audit, cross-network results, calibration/OOD curves, CPU/resource measurements on declared hardware, and browser proof that displayed outputs match persisted backend records.

### Stage 18 — Expanded Digital Twin and operator-controlled remediation

**Purpose:** Predict compatibility and operational effects, then verify only inside the controlled lab.

**Work:**

- Extend the existing Configuration Security Twin with peer capability and multi-tunnel compatibility constraints, certificate rotation, IKEv1-to-IKEv2 migration, PFS/DH changes, lifetime/DPD changes, MTU, NAT-T, latency/loss, and rekey collision/failure scenarios.
- Every simulation output remains `PROJECTED`; list assumptions, unknown peer capabilities, affected tunnels, expected impact, regression risk, and required proof obligations.
- Support explicit modes: Observe, Recommend, and Lab-Validated. Production change delivery is disabled in this roadmap. A human approval record must bind approver, target, exact patch/config hash, policy/model versions, change window, expiry, and rollback artifact.
- Make lab changes only through typed allowlisted operations. Require pre-change snapshot and hash, syntax/config validation, fresh SA/SPI evidence, equivalent workload, fresh PCAP hash, complete reanalysis, and claim ledger.
- Derive rollback thresholds from measured service objectives and scenario data. Cover tunnel absence, authentication/rekey failure, packet loss, latency/throughput regression, MTU/fragmentation, and compliance regression. Unknown health does not equal success.

**Exit evidence:** Twin regression matrix, unauthorized/stale approval rejection tests, rollback drills for each trigger, no-production-network proof, and a before/projected/lab-verified UI sequence.

### Stage 19 — Security scenario replay and forensic reproducibility

**Purpose:** Make both regression scenarios and historical analyses repeatable.

**Work:**

- Maintain a versioned lab scenario catalog for weak transforms, weak DH, IKEv1 exposure, PFS variation, rekey/DPD failure, NAT-T, packet loss, MTU/fragmentation, tunnel flapping, metadata anomaly, and configuration drift. Each scenario includes topology, config, workload, expected packets/events, expected evidence, expected findings, safe remediation, resource limits, and teardown proof.
- Call this “lab scenario replay” in product language; reserve attack language for a clearly bounded research experiment, not an implication that production attacks were performed.
- Add a forensic replay bundle that pins capture SHA-256, parser/dissector version, normalization schema, application build/container digest, policy bundle hash, model and feature schema hashes, dataset/threshold version, analysis timestamp, and evidence graph hash.
- A replay with identical pinned inputs should be deterministic for deterministic subsystems. ML repeatability documents hardware/runtime tolerances and inference determinism separately. New policy/model results create a new run and do not rewrite prior findings.

**Exit evidence:** Golden scenario manifests, deterministic replay comparison, intentional tamper detection, and a documented explanation for any nondeterministic output.

### Stage 20 — SOC workflow, browser UX, and evidence-first reporting

**Purpose:** Make continuous and forensic work usable for operators, not only technically present in APIs.

**Work:**

- Create a monitoring dashboard for active tunnels, event/alert queue, exposure, drift, risk-vector dimensions, anomaly and unknown states, scanner coverage/freshness, and sensor health. Use live updates with reconnect/resume and REST-backed durable state.
- Preserve the existing analysis routes and add clear navigation between monitoring, asset inventory, assessment jobs, forensic runs, evidence, and remediation. Every visual metric links to its evidence and source timestamp.
- For all states, design and implement loading, no data, partial results, unknown evidence, stale scanner/feed, offline service, timeout, permission/scope rejection, and retry/cancel behavior. Never show success-shaped numbers for placeholder or unavailable data.
- Browser verification must cover the full workflow with a real persisted analysis and authorized lab fixture: ingest/upload, live-capture authorization, protocol, SA/flow, traffic inference, security/risk vector, drift/certificates, evidence, reports, AI explanations, and lab remediation. Check desktop and narrow/mobile layouts, visible focus, keyboard navigation, contrast, labels, table semantics, chart text alternatives, and horizontal overflow.
- Distinguish a frontend route returning HTTP 200 from a functioning end-to-end feature. Record API calls, backend state, browser console errors, and evidence IDs for the verified flow.
- Reports include scope, capture and source hashes, limitations, unknowns, tool/model/policy versions, scanner coverage and freshness, and remediation proof state.

**Exit evidence:** Browser run report with screenshots or saved artifacts, route/API/session IDs, responsive and accessibility findings, zero unexplained console errors, and a populated end-to-end workflow with backend evidence.

### Stage 21 — Deployment, toolchain, and operational hardening

**Purpose:** Package a reproducible, supportable, local-first system.

**Work:**

- Define supported deployment profiles: offline forensic workstation, local single-node analysis, and authorized monitoring sensor plus local backend. Keep optional scanner integrations disabled until explicitly configured.
- Pin and inventory application, database, TShark/Wireshark, strongSwan, Nmap/ike-scan/Scapy/Greenbone adapters, model, policy, and feed versions. Use signed/checksummed artifacts and a supported update/rollback process.
- Add role-based access and audit controls for asset inventory, assessment scope approval, capture access, report export, model/policy updates, and lab remediation. Keep secrets out of reports, logs, prompts, and manifests.
- Test resource quotas, disk growth and retention, queue backpressure, restart/recovery, database backup/restore, sensor outage, feed staleness, AI/model outage, and air-gapped operation.
- Publish a software bill of materials, license notices, known limitations, and an operator runbook. Scanner permissions and network egress are explicit installation choices.

**Exit evidence:** Installation/upgrade/rollback rehearsal, backup restore, privilege audit, signed artifact inventory, air-gap test, and resource measurements on supported hardware.

### Stage 22 — Release acceptance and SIH rehearsal

**Purpose:** Validate claims through one integrated demonstration and a clear fallback sequence.

**Acceptance sequence:**

1. Confirm scope and lab health; record tool/runtime versions.
2. Run a real strongSwan tunnel scenario and generate a controlled workload.
3. Capture encrypted WAN traffic; hash and register the capture.
4. Run deterministic dissection and IKE/SA/ESP reconstruction.
5. Run persisted traffic classification, uncertainty/OOD, and feature attribution with the exact model manifest.
6. Evaluate deterministic policy and risk-vector dimensions; open a finding’s packet/config/scanner evidence.
7. Compare baseline configuration with observed state and show drift only where supported.
8. Project a Twin change, show compatibility assumptions and regression audit.
9. Require operator approval for the lab action, apply it only in the owned testbed, then establish a fresh SA, replay equivalent workload, recapture, and reanalyze.
10. Show resolved/unresolved/regressed proof obligations and the new run’s hashes.
11. Generate a report and ask the grounded analyst to explain already-produced facts with validated citations.
12. Demonstrate fallback: live lab → fresh analysis of a verified PCAP → cached validated session, clearly labeled.

**Release gate:** No claim of supported vendor coverage, CVE applicability, monitoring detection, model performance, remediation resolution, or “validated” status without the corresponding versioned evidence artifact and acceptance test.

## 3. Expert suggestions disposition

| Expert suggestion | Roadmap treatment |
|---|---|
| Real-time VPN monitoring and event alerts | Adopt in Stages 14 and 20; distinguish packet-visible events from endpoint-only facts. |
| Expand the Configuration Twin | Adopt in Stage 18; retain `PROJECTED` state and proof obligations. |
| Replace one score with a risk vector | Adopt in Stage 16; retain the score as a secondary trend/summary. |
| Configuration drift | Adopt in Stage 15 with explicit approved baseline and evidence provenance. |
| ATT&CK mapping | Adopt narrowly in Stage 16 using versioned STIX data and behavior-backed mappings. |
| Additional anomaly/baseline model | Adopt as an empirical, separate temporal baseline in Stage 17; do not conflate with current per-flow anomaly score. |
| Prediction explainability in UI | Adopt in Stage 17, showing units, direction, uncertainty, data sufficiency, and non-causal SHAP limits. |
| Adversarial ML testing | Adopt in Stage 17, lab-only, with degradation and error metrics. |
| Formal ML benchmark/cross-network validation | Adopt in Stage 17; include grouped splits, calibration, OOD, latency, resource use, and confidence intervals where sample size permits. |
| “Attack replay” catalog | Adopt as contained lab security-scenario replay in Stage 19; no production exploit execution. |
| Forensic replay | Adopt in Stage 19 with immutable pinned provenance and versioned re-analysis. |
| Policy versioning/diff | Adopt in Stage 16 with historical as-of comparisons. |
| Certificate intelligence | Adopt in Stage 15 from authorized config/runtime evidence; passive encrypted captures alone may be insufficient. |
| Multi-vendor support | Defer beyond the first strongSwan adapter until each vendor has validated import fixtures and semantics. |
| SOC dashboard | Adopt in Stage 20 after reliable event ingestion and backend persistence. |
| Threat-intelligence correlation | Adopt as optional, freshness-bound supporting evidence in Stage 16; no automatic maliciousness verdict. |
| Stronger privileged-agent security | Adopt in Stages 13, 14, 18, and 21: typed allowlist, peer authentication, permissions, replay resistance, audit, sandboxing, and resource bounds. |
| Human approval | Adopt for scoped lab actions; production changes remain out of scope. |
| Measurable rollback | Adopt in Stage 18 with empirically selected triggers and rollback drills. |
| Evidence Explorer | Preserve existing surface and strengthen it in Stage 20 with source, version, timestamp, confidence, and complete claim lineage. |

## 4. Current repository and browser findings that shape this plan

These are inspection findings, not claims that the full product has been validated:

- The repository already contains TShark capture processing, strongSwan lab scenarios, reconstruction, a policy engine, scoring/risk, evidence graphs, ML models, a Configuration Twin, RAG, a Next.js interface, and a broad test suite. The expert improvements should extend and connect these assets.
- The working tree already contains user changes. Preserve them; this roadmap file is additive.
- Project memory has contradictory Stage 12/current-task status. The release manifest has model and embedding details that do not match `backend/app/core/config.py` or the model choices shown in the UI. Reconcile before a release claim.
- Static search found `Stage7InferenceService.classify_flow` but no application caller or `FlowClassification` constructor outside the model definition. Confirm this in Stage 0; the traffic endpoint reads stored classifications, so end-to-end ML should not be assumed.
- A local browser check rendered `/analyses`, `/analyses/new`, `/analyses/default/ai-analyst`, and `/analyses/default/remediation`. The API on port 8000 was unavailable; analysis history displayed “Failed to fetch,” and the AI health probe failed. Docker was not running, so backend/browser integration could not be verified.
- The remediation route displayed a `default` analysis with a completed pipeline and rendered fallback values `45.0` and `+52.0` despite no active analysis/backend connection. These values are frontend fallbacks, not verified results. This is a Stage 0 correctness and UX fix.
- The capture intake page rendered, but the browser pass did not submit/upload a capture or execute a live-capture job. The UI layout and backend workflow remain only partially verified.

## 5. Tool and source validation notes

- The expert’s strongSwan 6.1.0 example is supported by the vendor’s September 7, 2026 release announcement: it fixed eleven vulnerabilities and disabled IKEv1 by default. A specific advisory documents the IKEv2 rekey-collision issue [CVE-2026-78133](https://community.strongswan.org/blog/2026/09/07/strongswan-vulnerability-%28cve-2026-78133%29.html). Use this as a reason to inventory and validate versions, not as a claim that every deployment is affected.
- strongSwan recommends avoiding IKEv1 Aggressive Mode with PSK and notes risks from weak PSKs. [Security Recommendations](https://docs.strongswan.org/docs/latest/howtos/securityRecommendations.html)
- ike-scan’s upstream documentation describes IKE discovery, implementation fingerprinting, and Phase 1 transform enumeration, as well as sensitive features such as username enumeration and offline PSK cracking. Only the bounded, authorized discovery/enumeration capabilities belong in the default workflow. [ike-scan upstream project](https://github.com/royhills/ike-scan)
- Nmap documents UDP scanning and service/version detection; a UDP result may remain `open|filtered`, so it must be normalized as uncertain where the probe cannot distinguish the state. [UDP scan reference](https://nmap.org/book/man-port-scanning-techniques.html), [service and version detection](https://nmap.org/book/vscan.html)
- Scapy can construct and send packets at Layer 3 or Layer 2, which supports lab testing but justifies a typed lab-only privilege boundary. [Scapy usage documentation](https://scapy.readthedocs.io/en/stable/usage.html)
- Greenbone scanning depends on synchronized vulnerability-test, SCAP, CERT, and management data. Its Community Feed documentation explicitly provides no warranty or completeness promise; feed version and freshness must accompany results. [Feed synchronization](https://greenbone.github.io/docs/latest/22.4/source-build/feed-sync.html), [Community Feed glossary](https://greenbone.github.io/docs/latest/glossary.html)
- MITRE ATT&CK provides machine-readable STIX and TAXII data that can be version-pinned for controlled mapping. [ATT&CK data and tools](https://attack.mitre.org/resources/working-with-attack/)
- NVD defines CPE as product/platform identity and provides CVE applicability statements, but its CPE dictionary can be incomplete. Unknown product matches must remain unresolved rather than being reported as safe. [NVD CPE FAQs](https://nvd.nist.gov/general/faq-sections/cpe-faqs)

## 6. Non-negotiable engineering rules

1. Protocol facts and policy results remain deterministic. ML estimates encrypted workload classes and behavior; it does not decide cryptographic facts or compliance.
2. `UNKNOWN` is a valid result. Missing sensor, PCAP, config, feed, model, or peer data must remain visible as missing evidence.
3. No ESP decryption, PSK cracking, brute force, broad network scanning, or production configuration changes are part of the default product path.
4. Every scanner and packet-crafting action is authorized, scoped, rate-limited, resource-limited, auditable, and cancellable.
5. Every result links to source evidence, timestamp, tool/runtime version, policy/model version, and hash where applicable.
6. Keep the local-first design and graceful degradation: scanner, sensor, database, ML, or LLM failures must not create fabricated success or disable unrelated offline forensic analysis.
7. Preserve local Git state. No commit, push, reset, clean, stash, or destructive restore unless separately requested.
