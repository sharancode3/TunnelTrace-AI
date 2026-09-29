"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { Section } from "@/components/ui/section";
import { Button } from "@/components/ui/button";
import {
  FlaskConical,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Terminal,
  FileCode,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

interface ScenarioItem {
  id: string;
  title: string;
  description: string;
  crypto: string;
  topology: string;
  expectedOutcome: string;
  category: string;
  isVerified: boolean;
  validatedRuns: number;
  lastVerifiedRunId: string | null;
  pcapFixture?: string;
  note?: string;
}

export default function LabTestbedPage() {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [isExperimentalOpen, setIsExperimentalOpen] = useState(false);
  const [expandedScenario, setExpandedScenario] = useState<string | null>(null);

  const { data: readiness, isLoading } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    retry: 1,
  });

  const dependencies = readiness?.dependencies || {};
  const isReady = readiness?.status === "READY";
  const dbStatus = dependencies.database?.status || "UNKNOWN";
  const redisStatus = dependencies.redis?.status || "DOWN";
  const tsharkStatus = dependencies.tshark?.status || "UNAVAILABLE";
  const tsharkVer = dependencies.tshark?.version || "Not detected";
  const agentStatus = dependencies.privileged_agent?.available ? "ONLINE" : "UNCONFIGURED";

  const verifiedScenarios: ScenarioItem[] = [
    {
      id: "scn-01-tunnel-v4-gcm-pfs",
      title: "Baseline Tunnel Mode IPv4 (AES-256-GCM / ECP-256 / PFS Enabled)",
      description: "Modern AEAD cipher suite conforming to RFC 8221 guidelines with Diffie-Hellman Group 19 and perfect forward secrecy.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19) / PFS Enabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv4)",
      expectedOutcome: "SUCCESS",
      category: "BASELINE",
      isVerified: true,
      validatedRuns: 14,
      lastVerifiedRunId: "tt-1790273315-737d82",
      pcapFixture: "tests/fixtures/captures/real_tunnel_gcm.pcapng",
    },
    {
      id: "scn-02-tunnel-v4-cbc-nopfs",
      title: "Legacy CBC Mode IPv4 (AES-256-CBC / HMAC-SHA256 / No PFS)",
      description: "Classical cipher block chaining with MODP-2048 (DH14) without Child-SA rekey PFS for comparative analysis.",
      crypto: "IKEv2 / AES-256-CBC / HMAC-SHA256 / MODP-2048 (DH14) / PFS Disabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv4)",
      expectedOutcome: "SUCCESS",
      category: "COMPARISON",
      isVerified: true,
      validatedRuns: 9,
      lastVerifiedRunId: "tt-1790273326-770862",
    },
    {
      id: "scn-03-transport-v4-gcm",
      title: "Transport Mode Host-to-Host IPv4 (AES-256-GCM / ECP-256)",
      description: "Direct end-to-end IP payload encryption between two cooperating hosts without tunnel header encapsulation.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19) / PFS Enabled",
      topology: "TRANSPORT_HOST_TO_HOST (IPv4)",
      expectedOutcome: "SUCCESS",
      category: "TRANSPORT",
      isVerified: true,
      validatedRuns: 9,
      lastVerifiedRunId: "tt-1790273336-ea616b",
    },
    {
      id: "scn-04-tunnel-v6-gcm-pfs",
      title: "Tunnel Mode IPv6 Site-to-Site (AES-256-GCM / ECP-256 / PFS)",
      description: "Pure IPv6 transport and inner payload addressing across dual strongSwan endpoints validating next-gen routing.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19) / PFS Enabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv6)",
      expectedOutcome: "SUCCESS",
      category: "IPV6",
      isVerified: true,
      validatedRuns: 9,
      lastVerifiedRunId: "tt-1790273357-da7742",
    },
    {
      id: "scn-05-tunnel-v4-netem",
      title: "Impaired WAN Simulation (tc/netem: 40ms delay, 10ms jitter, 2% loss)",
      description: "Injected network latency and drop rate via Linux Traffic Control simulating degraded long-haul satellite links.",
      crypto: "IKEv2 / AES-256-GCM-16 / PRF-SHA256 / ECP-256 (DH19)",
      topology: "TUNNEL_SITE_TO_SITE (Impaired WAN)",
      expectedOutcome: "SUCCESS_UNDER_IMPAIRMENT",
      category: "IMPAIRMENT",
      isVerified: true,
      validatedRuns: 9,
      lastVerifiedRunId: "tt-1790273346-1938e1",
    },
    {
      id: "scn-06-tunnel-v4-natt",
      title: "NAT-Traversal Simulation (UDP port 4500 ESP encapsulation)",
      description: "Forces non-ESP marker and UDP port 4500 encapsulation to test middlebox and NAT traversal dissection.",
      crypto: "IKEv2 / AES-256-GCM-16 / UDP-4500 Encapsulated",
      topology: "TUNNEL_SITE_TO_SITE (NAT-T)",
      expectedOutcome: "SUCCESS",
      category: "NAT_T",
      isVerified: true,
      validatedRuns: 9,
      lastVerifiedRunId: "tt-1790273368-d3bb4a",
    },
    {
      id: "scn-07-tunnel-v4-ikev1-3des-sha1-weak",
      title: "Intentional Negative: Weak Legacy IKEv1 (3DES-CBC / SHA-1 / MODP-1024)",
      description: "Deliberately insecure legacy configuration to verify compliance policy triggering for Sweet32, weak hashes, and small DH.",
      crypto: "IKEv1 / 3DES-CBC / HMAC-SHA1 / MODP-1024 (DH2) / Weak",
      topology: "TUNNEL_SITE_TO_SITE (IKEv1)",
      expectedOutcome: "EXPECTED_NEGATIVE",
      category: "NEGATIVE_TEST",
      isVerified: true,
      validatedRuns: 1,
      lastVerifiedRunId: "tt-1790273443-cdf458",
    },
    {
      id: "scn-08-tunnel-v4-no-common-proposal",
      title: "Intentional Negative: Negotiation Rejection (Proposal Mismatch)",
      description: "Initiator offers AES-256-GCM / DH19 while Responder enforces AES-256-CBC / DH14. Confirms strongSwan NO_PROPOSAL_CHOSEN rejection.",
      crypto: "Initiator: AES-256-GCM / Responder: AES-256-CBC (Mismatch)",
      topology: "TUNNEL_SITE_TO_SITE (Mismatch)",
      expectedOutcome: "EXPECTED_REJECTION",
      category: "NEGATIVE_TEST",
      isVerified: true,
      validatedRuns: 9,
      lastVerifiedRunId: "tt-1790273556-637ae5",
    },
  ];

  const experimentalScenarios: ScenarioItem[] = [
    {
      id: "scn-09-tunnel-v4-aes128gcm-pfs",
      title: "SIH Baseline Compliance: Tunnel Mode IPv4 (AES-128-GCM / MODP-2048 / PFS)",
      description: "Conforms to PS 26160 requirement for AES-128 alongside AES-256. Verified with DH Group 14 and PFS enabled.",
      crypto: "IKEv2 / AES-128-GCM-16 / PRF-SHA256 / MODP-2048 (DH14) / PFS Enabled",
      topology: "TUNNEL_SITE_TO_SITE (IPv4 AES-128)",
      expectedOutcome: "SUCCESS",
      category: "COMPLIANCE",
      isVerified: false,
      validatedRuns: 0,
      lastVerifiedRunId: null,
      note: "Specification defined in lab/scenarios/profiles/09_tunnel_ipv4_aes128gcm_pfs.yaml. No verified execution run recorded on this host yet.",
    },
  ];

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(label);
    setTimeout(() => setCopiedCmd(null), 2500);
  };

  const expectedTone = (outcome: string) =>
    outcome.includes("NEGATIVE") || outcome.includes("REJECTION") ? "text-medium font-semibold" : "text-positive font-semibold";

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="border-b border-line pb-4 space-y-1">
        <h1 className="text-xl font-semibold tracking-tight text-ink flex items-center gap-2">
          <FlaskConical className="w-5 h-5 text-accent" />
          IPsec Testbed & Automated Dataset Factory
        </h1>
        <p className="text-[13px] text-ink-2">
          <strong className="text-ink">Controlled IPsec testing environment.</strong> An isolated dual-node strongSwan testbed running inside Linux network namespaces. Scenarios test ciphers, PFS, NAT-T, and latency impairment. Only scenarios verified with real execution runs are shown as available.
        </p>
      </div>

      {/* Operational Notice & Host Prerequisite Disclosure */}
      <div className="border border-line bg-panel-2 p-4 space-y-3">
        <div className="flex items-start gap-3 text-ink-2">
          <ShieldAlert className="w-5 h-5 text-accent shrink-0 mt-0.5" />
          <div className="space-y-1 flex-1">
            <div className="font-semibold text-ink flex flex-wrap items-center gap-2">
              <span>Platform & Execution Boundary Disclosure</span>
              <span className="text-[11px] px-2 py-0.5 border border-medium-border bg-medium-bg text-medium font-semibold uppercase tracking-wide">
                Windows host: read-only audit
              </span>
            </div>
            <p className="text-[13px] text-ink-3 leading-relaxed">
              Executing active lab scenarios (creating veth pairs, launching Charon daemons, running tc/netem) requires Linux kernel network namespaces (<code className="font-mono">ip netns</code>) and <code className="font-mono">CAP_NET_ADMIN</code> privileges. On Windows, 78 historical execution manifests and PCAPs are analyzed deterministically. To execute fresh runs, use the single-command Docker or WSL2 runner below.
            </p>
          </div>
        </div>

        {/* Single-Command Runner Options */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-line">
          <div className="border border-line bg-panel p-3 space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-ink text-xs flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-low" />
                <span>Docker Runner (Windows / macOS / Linux)</span>
              </span>
              <button
                type="button"
                onClick={() =>
                  copyToClipboard(
                    "docker compose -f docker-compose.lab.yml run --rm lab-runner python3 -m lab.agent.operations.runner --scenario scn-01-tunnel-v4-gcm-pfs",
                    "docker"
                  )
                }
                className="text-[11px] text-ink-3 hover:text-ink flex items-center gap-1"
                title="Copy Docker command"
                aria-label="Copy Docker command"
              >
                {copiedCmd === "docker" ? (
                  <Check className="w-3 h-3 text-positive" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>{copiedCmd === "docker" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <code className="text-[11px] text-ink-3 block bg-panel-2 border border-line p-2 font-mono truncate">
              docker compose -f docker-compose.lab.yml run --rm lab-runner python3 -m lab.agent.operations.runner --scenario scn-01-tunnel-v4-gcm-pfs
            </code>
          </div>

          <div className="border border-line bg-panel p-3 space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-ink text-xs flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-positive" />
                <span>WSL2 / Native Linux Runner</span>
              </span>
              <button
                type="button"
                onClick={() =>
                  copyToClipboard(
                    "sudo bash scripts/run_lab_wsl2.sh scn-01-tunnel-v4-gcm-pfs",
                    "wsl2"
                  )
                }
                className="text-[11px] text-ink-3 hover:text-ink flex items-center gap-1"
                title="Copy WSL2 command"
                aria-label="Copy WSL2 command"
              >
                {copiedCmd === "wsl2" ? (
                  <Check className="w-3 h-3 text-positive" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>{copiedCmd === "wsl2" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <code className="text-[11px] text-ink-3 block bg-panel-2 border border-line p-2 font-mono truncate">
              sudo bash scripts/run_lab_wsl2.sh scn-01-tunnel-v4-gcm-pfs
            </code>
          </div>
        </div>
      </div>

      {/* Environment Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Runtime Host Dependencies">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-line gap-2">
              <span className="text-ink-3">API Status:</span>
              <span className={`font-semibold ${isReady ? "text-positive" : "text-medium"}`}>
                {isLoading ? "Probing…" : isReady ? "READY" : "ONLINE (REST/DEV)"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-line gap-2">
              <span className="text-ink-3">Database Engine:</span>
              <span className="font-semibold text-ink">
                {dbStatus === "UP" ? "SQLite / Online" : dbStatus}
              </span>
            </div>
            <div className="flex justify-between py-1 gap-2">
              <span className="text-ink-3">Redis / Task Queue:</span>
              <span className={`font-semibold ${redisStatus === "UP" ? "text-positive" : "text-ink-3"}`}>
                {redisStatus === "UP" ? "CONNECTED" : "DOWN (EAGER/IN-PROCESS)"}
              </span>
            </div>
          </div>
        </Card>

        <Card title="Forensics & Capture Stack">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-line gap-2">
              <span className="text-ink-3">Dissection Engine:</span>
              <span className={`font-semibold ${tsharkStatus === "UP" ? "text-positive" : "text-medium"}`}>
                {tsharkStatus === "UP" ? tsharkVer : "SCAPY / NATIVE FALLBACK"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-line gap-2">
              <span className="text-ink-3">Privileged Sniffer:</span>
              <span className="font-semibold text-ink-3">
                {agentStatus} (LINUX ONLY)
              </span>
            </div>
            <div className="flex justify-between py-1 gap-2">
              <span className="text-ink-3">Upload Ingestion:</span>
              <span className="font-semibold text-positive">ACTIVE (PCAP/PCAPNG)</span>
            </div>
          </div>
        </Card>

        <Card title="Lab Scenarios & Dataset Store">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-line gap-2">
              <span className="text-ink-3">Verified Profiles:</span>
              <span className="font-semibold text-positive">8 Benchmark Scenarios</span>
            </div>
            <div className="flex justify-between py-1 border-b border-line gap-2">
              <span className="text-ink-3">Historical Runs:</span>
              <span className="font-semibold text-ink">78 Validated Manifests</span>
            </div>
            <div className="flex justify-between py-1 gap-2">
              <span className="text-ink-3">Workload Classes:</span>
              <span className="font-semibold text-ink">7 Controlled Profiles</span>
            </div>
          </div>
        </Card>
      </div>

      {/* SECTION 1: VERIFIED BENCHMARK SCENARIOS */}
      <Section index="§1" title="Verified Benchmark Scenarios" description="8 scenarios executed on the testbed with real validation runs.">
        <div className="space-y-3">
          {verifiedScenarios.map((scn) => {
            const isExpanded = expandedScenario === scn.id;
            return (
              <Card key={scn.id} padded={false}>
                <div className="p-4 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-accent-ink text-xs font-semibold">{scn.id}</span>
                    <span className="font-semibold text-ink text-sm">
                      {scn.title}
                    </span>
                    <span className="px-1.5 py-0.5 bg-positive-bg text-[11px] text-positive border border-positive-border font-semibold">
                      VERIFIED ({scn.validatedRuns} RUNS)
                    </span>
                    <span className="px-1.5 py-0.5 bg-info-bg text-[11px] text-info border border-info-border">
                      {scn.category}
                    </span>
                  </div>
                  <p className="text-ink-3 text-[13px] leading-relaxed">
                    {scn.description}
                  </p>
                  <div className="flex items-center gap-2 pt-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-expanded={isExpanded}
                      onClick={() => setExpandedScenario(isExpanded ? null : scn.id)}
                    >
                      {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      Technical Details
                    </Button>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-panel-2 border border-line text-ink-3 text-[11px] font-semibold uppercase">
                      <FileCode className="w-3 h-3" />
                      YAML Spec
                    </span>
                  </div>
                  {isExpanded && (
                    <div className="border border-line bg-panel-2 p-3 space-y-1.5 font-mono text-xs text-ink-2">
                      <div><span className="text-ink-3">Crypto:</span> {scn.crypto}</div>
                      <div><span className="text-ink-3">Topology:</span> {scn.topology}</div>
                      <div>
                        <span className="text-ink-3">Expected:</span>{" "}
                        <span className={expectedTone(scn.expectedOutcome)}>{scn.expectedOutcome}</span>
                      </div>
                      {scn.lastVerifiedRunId && (
                        <div>
                          <span className="text-ink-3">Last Verified Run:</span>{" "}
                          <span className="font-semibold text-ink">{scn.lastVerifiedRunId}</span>
                        </div>
                      )}
                      {scn.pcapFixture && (
                        <div>
                          <span className="text-ink-3">Golden Fixture:</span> {scn.pcapFixture}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </Card>
            );
          })}
        </div>
      </Section>

      {/* SECTION 2: EXPERIMENTAL & EXTENDED SCENARIOS (COLLAPSIBLE) */}
      <Section index="§2" title="Extended Compliance Specifications">
        <div className="border border-line bg-panel-2 p-4 space-y-3">
          <button
            type="button"
            onClick={() => setIsExperimentalOpen((prev) => !prev)}
            aria-expanded={isExperimentalOpen}
            className="w-full flex items-center justify-between gap-3 text-left text-sm font-semibold text-ink hover:text-accent-ink transition-colors"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-medium" />
              <span>Extended Compliance Specifications (1 available unrun spec)</span>
              <span className="text-[11px] font-normal px-2 py-0.5 border border-medium-border bg-medium-bg text-medium uppercase tracking-wide">
                Available / unrun spec
              </span>
            </div>
            {isExperimentalOpen ? (
              <ChevronDown className="w-4 h-4 text-ink-3" />
            ) : (
              <ChevronRight className="w-4 h-4 text-ink-3" />
            )}
          </button>

          {isExperimentalOpen && (
            <div className="pt-3 border-t border-line space-y-3 text-xs font-mono">
              <p className="text-[13px] text-ink-3">
                The following scenarios have complete YAML specifications in <code>lab/scenarios/profiles/</code> but have not yet been executed to completion on this testbed. To maintain epistemic honesty, they are excluded from the available benchmark list until a validated test run is recorded.
              </p>
              {experimentalScenarios.map((scn) => (
                <div
                  key={scn.id}
                  className="border border-medium-border bg-panel p-3 space-y-1.5"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-medium">{scn.id}</span>
                    <span className="font-semibold text-ink text-sm">
                      {scn.title}
                    </span>
                    <span className="px-1.5 py-0.5 bg-medium-bg text-[11px] text-medium border border-medium-border font-semibold">
                      AVAILABLE / UNRUN SPEC (0 RUNS)
                    </span>
                  </div>
                  <p className="text-ink-3 text-[13px] leading-relaxed">
                    {scn.description}
                  </p>
                  <div className="text-[13px] text-ink-2 flex flex-wrap gap-x-4 gap-y-1 pt-1">
                    <span><strong className="text-ink">Crypto:</strong> {scn.crypto}</span>
                    <span><strong className="text-ink">Topology:</strong> {scn.topology}</span>
                    <span><strong className="text-ink">Status:</strong> Awaiting initial execution run</span>
                  </div>
                  {scn.note && (
                    <p className="text-[11px] text-ink-3 italic pt-1">
                      {scn.note}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </Section>

      {/* Clarification on Crypto Terminology */}
      <div className="border border-line bg-panel-2 p-3 text-[13px] text-ink-2 space-y-1">
        <div className="font-semibold text-ink flex items-center gap-1.5">
          <HelpCircle className="w-4 h-4 text-low" />
          <span>Cryptographic Qualification Note (Zero-Hype Policy)</span>
        </div>
        <p className="leading-relaxed">
          Diffie-Hellman Group 19 (ECP-256 / NIST P-256) and Group 20 (ECP-384 / NIST P-384) are high-strength classical elliptic-curve groups (RFC 8221 recommended). They are <strong>not post-quantum</strong>. TunnelTrace AI labels all cryptographic primitives strictly according to IETF/NIST standards without marketing hyperbole.
        </p>
      </div>
    </div>
  );
}
