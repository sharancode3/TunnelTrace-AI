"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Card } from "@/components/ui/card";
import { Section, Subsection } from "@/components/ui/section";
import { Button, ButtonLink } from "@/components/ui/button";
import {
  UploadCloud,
  Globe,
  Network,
  ShieldCheck,
  Radio,
  ShieldAlert,
  Bot,
  FileText,
  FlaskConical,
  ChevronRight,
  ChevronLeft,
  ArrowRight,
  CheckCircle2,
  HelpCircle,
} from "lucide-react";

interface StepDetail {
  id: number;
  title: string;
  shortLabel: string;
  tagline: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  inputs: string[];
  outputs: string[];
  standards: string[];
  liveLink: string;
  liveLinkLabel: string;
}

const STEPS: StepDetail[] = [
  {
    id: 1,
    title: "Step 1: Capture Ingestion & Provenance Lineage",
    shortLabel: "1. Ingestion",
    tagline: "Cryptographic hashing, header validation, and immutable storage",
    icon: UploadCloud,
    description:
      "The system accepts standard binary packet capture files (.pcap and .pcapng). Upon upload, it instantly calculates SHA-256 and MD5 cryptographic digests, inspects the capture magic numbers, validates file size limits, and persists the raw artifact into immutable storage. A tamper-evident lineage record is bound to every subsequent analysis.",
    inputs: [".pcap or .pcapng binary capture files", "Capture profile preset (IPsec-relevant)"],
    outputs: ["Immutable Capture record (UUID)", "Cryptographic SHA-256 digest", "Packet count & duration metadata"],
    standards: ["PCAP / PCAPNG Specification", "FIPS 180-4 (SHA-256 Hashing)"],
    liveLink: "/analyses/new",
    liveLinkLabel: "Go to Ingest Capture",
  },
  {
    id: 2,
    title: "Step 2: Authorized Asset Discovery & Pre-Scan",
    shortLabel: "2. Discovery",
    tagline: "Bounded Nmap port scanning for IKE and NAT-Traversal endpoints",
    icon: Globe,
    description:
      "Before or alongside capture analysis, authorized asset discovery scans approved IP subnets for active VPN gateways on UDP port 500 (IKE) and UDP port 4500 (NAT-Traversal / ESP encapsulation). The system preserves observational ambiguity: UDP states like 'open|filtered' are faithfully retained rather than being forced into false certainty.",
    inputs: ["Approved target IP / CIDR scope", "Operator authorization attestation code"],
    outputs: ["Discovered VPN gateway host records", "Service identifications (isakmp, ipsec-nat-t)", "Preserved port states (open, open|filtered)"],
    standards: ["RFC 7296 §3.1 (IKE UDP Port 500)", "RFC 3948 (UDP Port 4500 NAT-T)"],
    liveLink: "/discovery",
    liveLinkLabel: "Go to Asset Discovery",
  },
  {
    id: 3,
    title: "Step 3: Headless Protocol Dissection & State Reconstruction",
    shortLabel: "3. Dissection",
    tagline: "Headless TShark/Scapy parsing of IKEv1, IKEv2, and ESP tunnels",
    icon: Network,
    description:
      "Headless dissection engines (TShark and Scapy) parse the binary capture into structured JSON protocol trees. The system reconstructs IKE Security Associations (IKE_SA_INIT, IKE_AUTH) and Child SA ESP tunnels, mapping SPI identifiers, Diffie-Hellman public values, encryption transforms, and PRF algorithms at exact packet byte offsets.",
    inputs: ["Verified raw PCAP/PCAPNG file", "Link-layer frame sequence"],
    outputs: ["Hierarchical protocol observation tree", "IKE SA proposals & transform matrices", "ESP unidirectional flow records (SPI, packets, bytes)"],
    standards: ["RFC 7296 (IKEv2 Protocol)", "RFC 4303 (IPsec ESP)", "RFC 2409 (IKEv1)"],
    liveLink: "/analyses",
    liveLinkLabel: "Select an Analysis to Inspect Dissection",
  },
  {
    id: 4,
    title: "Step 4: Deterministic Cryptographic Policy & Posture Scoring",
    shortLabel: "4. Policy & Scoring",
    tagline: "NIST SP 800-77 & RFC 8247 compliance audit with mathematical scoring",
    icon: ShieldCheck,
    description:
      "The policy engine evaluates observed cryptographic transforms against authoritative guidelines (NIST SP 800-77 Rev. 1, RFC 8247, RFC 8221, and ANSSI). Violations (e.g. deprecated 3DES, MD5, small DH groups) incur deterministic point deductions. Posture score is gated by evidence coverage—if a capture has 0 IPsec packets, it is labeled NOT ASSESSABLE instead of receiving a fake 100/100 score.",
    inputs: ["Negotiated cryptographic transforms", "Observed transform IDs", "Rekey & lifetime parameters"],
    outputs: ["Itemized security findings (CRIT, HIGH, MED, LOW)", "Compliance matrix pass/fail scorecards", "Evidence-weighted posture score (0–100 or NOT ASSESSABLE)"],
    standards: ["NIST SP 800-77 Rev. 1", "RFC 8247 (IKEv2 Cryptographic Algorithms)", "RFC 8221 (ESP & AH Suites)"],
    liveLink: "/analyses",
    liveLinkLabel: "View Security Assessments",
  },
  {
    id: 5,
    title: "Step 5: Multimodal Machine Learning Traffic Profiling",
    shortLabel: "5. Traffic ML",
    tagline: "1D-CNN + XGBoost encrypted flow classification with TreeSHAP explainability",
    icon: Radio,
    description:
      "Without decrypting ciphertext payloads, the ML engine profiles application traffic traversing encrypted ESP tunnels. A 1D-CNN inspects packet length and direction sequences, while XGBoost classifies statistical flow features (inter-arrival times, burst entropy, byte ratios). Calibrated probabilities, out-of-distribution (OOD) detection, and TreeSHAP explainability indicate exactly why a flow was classified as VoIP, Video, Web, or DNS.",
    inputs: ["ESP packet sequences (length, direction, timestamp)", "Statistical flow aggregates (duration, byte volume)"],
    outputs: ["Predicted application class (VoIP, Video, Web, etc.)", "Calibrated confidence score & OOD flag", "TreeSHAP feature importance ranking"],
    standards: ["Encrypted Traffic Analysis (ETA) Standards", "TreeSHAP Explainability (Lundberg et al.)"],
    liveLink: "/analyses",
    liveLinkLabel: "View Traffic & ML Intelligence",
  },
  {
    id: 6,
    title: "Step 6: Vulnerability Intelligence & Threat Matrix",
    shortLabel: "6. Threat Matrix",
    tagline: "Greenbone OpenVAS CVE correlation and MITRE ATT&CK mapping",
    icon: ShieldAlert,
    description:
      "Discovered VPN vendor implementations (strongSwan, Cisco ASA, Fortinet FortiOS) and protocol weaknesses are correlated against National Vulnerability Database (NVD) CVE feeds via Greenbone OpenVAS reports. Vulnerabilities are mapped to MITRE ATT&CK tactics (Initial Access, Defense Evasion, Impact) with tailored remediation playbooks.",
    inputs: ["Greenbone OpenVAS XML reports", "Vendor ID fingerprint observations", "Discovered software versions"],
    outputs: ["Correlated CVE records (e.g. CVE-2023-35945)", "CVSS v3.1 severity metrics", "MITRE ATT&CK enterprise technique mappings"],
    standards: ["MITRE ATT&CK Enterprise Matrix", "NIST NVD / CVSS v3.1 Specification"],
    liveLink: "/vulnerabilities",
    liveLinkLabel: "View Vulnerability Feed",
  },
  {
    id: 7,
    title: "Step 7: Grounded AI Security Analyst (Dual-Mode)",
    shortLabel: "7. AI Analyst",
    tagline: "Instant zero-latency database fact search + Local Ollama conversational RAG",
    icon: Bot,
    description:
      "TunnelTrace AI features a grounded dual-mode AI Analyst. In 'Evidence Search' mode, users get sub-millisecond, deterministic retrieval of database facts and RFC citations without model latency. In 'Local Ollama' mode, on-premise models (Qwen, Gemma) synthesize findings under a strict Fact-Lock and Claim Gate that rejects unverified citations and enforces canonical abstention on unassessable captures.",
    inputs: ["User security questions", "Fact-locked database context store", "Normative RFC/NIST vector chunks"],
    outputs: ["Sub-millisecond structured evidence tables", "Grounded remediation narratives", "Claim-gate verified RFC & CVE citations"],
    standards: ["RFC 8247, RFC 8221, NIST SP 800-77", "Claim-Gated Grounded RAG Architecture"],
    liveLink: "/analyses",
    liveLinkLabel: "Test AI Security Analyst",
  },
  {
    id: 8,
    title: "Step 8: Publication-Grade Audit Reports & Lineage Verification",
    shortLabel: "8. Reports",
    tagline: "Cryptographic SHA-256 bound PDF, JSON, and CSV exports for SOC compliance",
    icon: FileText,
    description:
      "The platform generates deterministic, immutable compliance and forensic reports. Reports embed the source PCAP's SHA-256 hash, NIST compliance scorecards, packet hex dump references, and step-by-step remediation snippets. Downloadable in JSON (STIX 2.1-ready), executive PDF, and CSV formats for SIEM ingestion.",
    inputs: ["Completed analysis snapshot", "Integrity-verified source capture artifact"],
    outputs: ["Audit-ready Executive Summary PDF", "STIX 2.1 JSON assessment bundle", "Tabular CSV findings log"],
    standards: ["NIST SP 800-77 Audit Guidelines", "STIX 2.1 Machine-Readable Security Bundles"],
    liveLink: "/analyses",
    liveLinkLabel: "Download Audit Reports",
  },
];

export default function HowItWorksPage() {
  const [activeStepId, setActiveStepId] = useState<number>(1);
  const currentStep = STEPS.find((s) => s.id === activeStepId) || STEPS[0];
  const Icon = currentStep.icon;

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="border border-line bg-panel p-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-line pb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-accent-press flex items-center justify-center text-on-accent font-mono font-semibold text-sm shrink-0">
              TT
            </div>
            <div>
              <span className="inline-block text-[11px] font-mono px-2 py-0.5 border border-line bg-panel-2 text-ink-2 font-semibold uppercase">
                SIH 2026 · PS 26160
              </span>
              <h1 className="text-xl font-semibold text-ink tracking-tight mt-1.5">
                How TunnelTrace AI Works
              </h1>
            </div>
          </div>
          <ButtonLink href="/analyses/new" variant="primary" size="sm">
            Try Live Ingestion
            <ArrowRight className="w-3.5 h-3.5" />
          </ButtonLink>
        </div>
        <p className="text-[13px] text-ink-2 leading-relaxed max-w-[65ch]">
          TunnelTrace AI is an epistemically honest IPsec VPN protocol analyzer designed for the National Technical Research Organisation (NTRO). It replaces black-box guessing with deterministic mathematical scoring, headless packet dissection, local machine learning, and claim-gated AI analyst assistance.
        </p>
      </div>

      {/* §1 Special Callout: What is the Lab & Testbed? */}
      <Section index="§1" title="What is the Lab & Testbed? (And Why Does It Exist?)">
        <div className="border border-low-border bg-low-bg p-4 space-y-3">
          <p className="text-[13px] leading-relaxed text-ink-2">
            Evaluators often ask: <em>&ldquo;How do we safely test weak or obsolete VPN configurations without attacking our live network?&rdquo;</em>
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="border border-line bg-panel p-3">
              <div className="font-semibold text-ink flex items-center gap-1.5 mb-1">
                <span className="w-2 h-2 bg-low" />
                <span>1. Dual-strongSwan Testbed</span>
              </div>
              <p className="text-ink-3 text-xs leading-relaxed">
                Spins up two isolated Linux network namespaces (Client & Gateway) connected by a virtual bridge.
              </p>
            </div>
            <div className="border border-line bg-panel p-3">
              <div className="font-semibold text-ink flex items-center gap-1.5 mb-1">
                <span className="w-2 h-2 bg-low" />
                <span>2. 9 Scenarios (8 Verified Benchmark, 1 Spec)</span>
              </div>
              <p className="text-ink-3 text-xs leading-relaxed">
                Pre-configured profiles: Modern AES-GCM (RFC 8221), Legacy 3DES-CBC, IPv6 Site-to-Site, NAT-T 4500, and Netem WAN loss.
              </p>
            </div>
            <div className="border border-line bg-panel p-3">
              <div className="font-semibold text-ink flex items-center gap-1.5 mb-1">
                <span className="w-2 h-2 bg-low" />
                <span>3. Ground-Truth PCAPs</span>
              </div>
              <p className="text-ink-3 text-xs leading-relaxed">
                Generates genuine, reproducible PCAPs with known keys for forensic verification and compliance benchmarking.
              </p>
            </div>
          </div>
          <div className="pt-1">
            <Link
              href="/lab"
              className="inline-flex items-center gap-1 text-[13px] font-semibold text-accent-ink hover:underline"
            >
              Explore the 9 Lab Scenarios (8 Verified, 1 Spec) in Lab Catalog
              <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </Section>
      {/* §2 Interactive Step-by-Step Flowchart */}
      <Section index="§2" title="The 8-Stage Investigation Flow" description="Select a stage to inspect its inputs, outputs, and normative standards.">
        <div className="space-y-4">
          {/* Horizontal Stepper Chips */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1" role="tablist" aria-label="Investigation stages">
            {STEPS.map((s) => {
              const StepIcon = s.icon;
              const isActive = s.id === activeStepId;
              return (
                <button
                  key={s.id}
                  role="tab"
                  aria-selected={isActive}
                  onClick={() => setActiveStepId(s.id)}
                  className={`flex items-center gap-1.5 px-3 h-9 text-xs font-mono whitespace-nowrap border shrink-0 transition-colors ${
                    isActive
                      ? "bg-accent-press text-on-accent border-accent font-semibold"
                      : "bg-panel text-ink-3 border-line hover:bg-panel-2 hover:text-ink"
                  }`}
                >
                  <StepIcon className="w-3.5 h-3.5 shrink-0" />
                  <span>{s.shortLabel}</span>
                </button>
              );
            })}
          </div>

          {/* Active Step Detail */}
          <Card padded={false}>
            <div className="p-5 space-y-5">
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-line pb-4">
                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center shrink-0 px-3.5 py-2.5 bg-panel-2 border border-line leading-none">
                    <span className="text-3xl font-mono font-bold tabular-nums text-ink">
                      {currentStep.id}
                    </span>
                    <span className="text-[11px] font-mono uppercase tracking-[0.06em] text-ink-3 mt-1.5">
                      of {STEPS.length}
                    </span>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start gap-2">
                      <Icon className="w-4 h-4 text-accent shrink-0 mt-1" />
                      <div className="min-w-0">
                        <h3 className="text-title font-semibold text-ink">
                          {currentStep.title}
                        </h3>
                        <p className="text-[13px] text-ink-3 mt-1">
                          {currentStep.tagline}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <ButtonLink
                  href={currentStep.liveLink}
                  variant="secondary"
                  size="sm"
                  className="shrink-0"
                >
                  <span>{currentStep.liveLinkLabel}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </ButtonLink>
              </div>

              {/* Description */}
              <div className="max-w-[65ch] text-[13px] text-ink-2 leading-relaxed border border-line bg-panel-2 p-4">
                {currentStep.description}
              </div>

              {/* 3 Technical Matrices: Inputs, Outputs, Standards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Subsection title="Data Inputs">
                  <ul className="space-y-1.5 text-ink-2 text-xs">
                    {currentStep.inputs.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-accent font-semibold">▸</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Subsection>

                <Subsection title="Stage Outputs">
                  <ul className="space-y-1.5 text-ink-2 text-xs">
                    {currentStep.outputs.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-positive shrink-0 mt-0.5" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Subsection>

                <Subsection title="Normative Standards">
                  <ul className="space-y-1.5 text-ink-2 text-xs">
                    {currentStep.standards.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-medium font-semibold">§</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Subsection>
              </div>

              {/* Stepper Navigation Footer */}
              <div className="flex items-center justify-between pt-4 border-t border-line text-xs font-mono">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setActiveStepId((prev) => Math.max(1, prev - 1))}
                  disabled={activeStepId === 1}
                >
                  <ChevronLeft className="w-4 h-4" />
                  <span>Previous Stage</span>
                </Button>

                <span className="text-ink-3 font-semibold">
                  {activeStepId} / {STEPS.length}
                </span>

                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => setActiveStepId((prev) => Math.min(STEPS.length, prev + 1))}
                  disabled={activeStepId === STEPS.length}
                >
                  <span>Next Stage</span>
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </Card>
        </div>
      </Section>

      {/* §3 Frequently Asked Questions / Epistemic Invariants */}
      <Section index="§3" title="Key Platform Questions & Design Principles">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <Card title="What packet files does the system support?">
            <p className="text-[13px] text-ink-2 leading-relaxed max-w-[62ch]">
              The system supports all standard binary <strong>.pcap</strong> and <strong>.pcapng</strong> capture files containing IKEv1, IKEv2, ESP, and AH protocol exchanges. Uploading non-IPsec captures (e.g. WireGuard, raw HTTP) is handled gracefully and labeled as unassessable.
            </p>
          </Card>

          <Card title="Why does a zero-evidence capture show NOT ASSESSABLE?">
            <p className="text-[13px] text-ink-2 leading-relaxed max-w-[62ch]">
              If a capture has 0 IKE handshakes and 0 ESP tunnels, giving it a 100/100 score would be a dangerous security lie. TunnelTrace AI strictly enforces <strong>epistemic honesty</strong>: zero evidence yields 0.0% coverage and a clear &lsquo;NOT ASSESSABLE&rsquo; status.
            </p>
          </Card>

          <Card title="How does Live Monitoring work without active VPN sensors?">
            <p className="text-[13px] text-ink-2 leading-relaxed max-w-[62ch]">
              The live monitoring dashboard connects via WebSocket to listen for heartbeat telemetry from remote Linux strongSwan collector sensors. In local development where no live VPN appliance is streaming, it honestly reports &lsquo;SENSORS STALE&rsquo;. You can click &lsquo;TEST LIVE PULSE&rsquo; to verify the live WebSocket streaming engine anytime.
            </p>
          </Card>

          <Card title="Does Machine Learning decrypt encrypted ESP payloads?">
            <p className="text-[13px] text-ink-2 leading-relaxed max-w-[62ch]">
              No. AES-GCM and AES-CBC ciphertext cannot be decrypted without key material. Instead, the 1D-CNN and XGBoost models profile statistical packet metadata (packet length patterns, inter-arrival times, burst entropy) to infer traffic categories (VoIP, Video, Web) with explainable TreeSHAP feature rankings.
            </p>
          </Card>
        </div>
      </Section>
    </div>
  );
}
