"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Section, Subsection } from "@/components/ui/section";
import { Stat, StatGrid } from "@/components/ui/stat";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { EvidenceStateBadge } from "@/components/ui/badge";
import {
  CopyableValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AlertTriangle, ChevronRight } from "lucide-react";

export default function ProtocolIntelligencePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [showRawDetail, setShowRawDetail] = useState(false);

  const {
    data: protocol,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["protocol", analysisId],
    queryFn: () => api.analyses.getProtocol(analysisId),
  });

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState
          compact
          title="Dissecting protocol frames…"
          description="Extracting IKE/ESP parameters from the capture."
        />
      </div>
    );
  }

  if (isError || !protocol) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load protocol intelligence"
          description={(error as any)?.message || "Unknown error"}
          action={
            <Button variant="secondary" size="sm" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  const { evidence_states } = protocol;
  const ikePacketCount = protocol.ikev1_packet_count + protocol.ikev2_packet_count;
  const encapsulationCount = protocol.esp_packet_count + protocol.ah_packet_count;

  const natTValue = protocol.nat_t_detected
    ? "UDP 4500 (NAT-T)"
    : ikePacketCount > 0
    ? "DIRECT / UDP 500"
    : "NOT OBSERVED (NO IKE)";

  const natTHint = protocol.nat_t_detected
    ? "UDP encapsulation with non-ESP marker detected."
    : ikePacketCount > 0
    ? "Standard direct UDP 500 handshake without NAT encapsulation."
    : "No IKE handshake observed in capture. Direct ESP over raw IP (protocol 50).";

  const chip =
    "px-2 py-0.5 bg-panel-2 border border-line text-ink-2 font-mono text-xs";

  const observedVersions = observedIkeVersions(protocol);

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold text-ink tracking-tight">
          Protocol Intelligence
        </h1>
        <p className="text-[13px] text-ink-2">
          IKEv1/IKEv2 handshake facts verified directly from the packets — which
          protocol version, mode, and cryptographic suites we could actually
          observe. Anything not observed is marked UNKNOWN, never guessed.
        </p>
      </header>

      <Section
        index="§1"
        title="Detection & Encapsulation"
        description="What the dissection found across every inspected frame."
      >
        <div className="border border-line bg-panel p-4 space-y-4">
          <StatGrid>
            <Stat
              label="IPsec Status"
              value={protocol.ipsec_detected ? "DETECTED" : "NOT OBSERVED"}
              tone={protocol.ipsec_detected ? "default" : "info"}
              hint={`Total frames inspected: ${protocol.total_packets_inspected}`}
            />
            <Stat
              label="IKE Negotiation Packets"
              value={ikePacketCount}
              hint={`IKEv1: ${protocol.ikev1_packet_count} · IKEv2: ${protocol.ikev2_packet_count}`}
            />
            <Stat
              label="Encapsulation (ESP / AH)"
              value={encapsulationCount}
              hint={`ESP: ${protocol.esp_packet_count} · AH: ${protocol.ah_packet_count}`}
            />
            <Stat
              label="NAT-T Traversal"
              value={natTValue}
              tone={protocol.nat_t_detected ? "low" : ikePacketCount > 0 ? "info" : "medium"}
              hint={natTHint}
            />
          </StatGrid>
        </div>

        <Table>
          <TableHeader>
            <tr>
              <TableHead>Fact</TableHead>
              <TableHead>Observed Value</TableHead>
              <TableHead>Interpretation</TableHead>
            </tr>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                IPsec Detected
              </TableCell>
              <TableCell mono>{protocol.ipsec_detected ? "YES" : "NO"}</TableCell>
              <TableCell className="text-ink-3">
                {protocol.ipsec_detected
                  ? "IPsec packets present in capture window."
                  : "No IPsec packet observed in this capture."}
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                Frames Inspected
              </TableCell>
              <TableCell mono>{protocol.total_packets_inspected}</TableCell>
              <TableCell className="text-ink-3">
                Every frame considered during dissection.
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                Observed IKE Versions
              </TableCell>
              <TableCell mono>{observedVersions}</TableCell>
              <TableCell className="text-ink-3">
                IKEv1 {protocol.ikev1_packet_count} packet(s) · IKEv2{" "}
                {protocol.ikev2_packet_count} packet(s).
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                Encapsulation
              </TableCell>
              <TableCell mono>
                ESP {protocol.esp_packet_count} · AH {protocol.ah_packet_count}
              </TableCell>
              <TableCell className="text-ink-3">
                Payload encapsulation counts observed on the wire.
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                NAT-T Traversal
              </TableCell>
              <TableCell mono>{natTValue}</TableCell>
              <TableCell className="text-ink-3">{natTHint}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </Section>

      <Section
        index="§2"
        title="Proposals & Key Exchange"
        description="Cryptographic transforms and Diffie-Hellman parameters read from unencrypted handshake frames."
        actions={
          evidence_states?.cipher_suites ? (
            <EvidenceStateBadge state={evidence_states.cipher_suites} />
          ) : undefined
        }
      >
        <Table>
          <TableHeader>
            <tr>
              <TableHead>Parameter</TableHead>
              <TableHead>Observed Values</TableHead>
              <TableHead>Evidence</TableHead>
            </tr>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                Cipher Suites (Encryption Algorithms)
              </TableCell>
              <TableCell>
                {protocol.observed_cipher_suites &&
                protocol.observed_cipher_suites.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {protocol.observed_cipher_suites.map(
                      (cipher: string, idx: number) => (
                        <span key={idx} className={chip}>
                          {cipher}
                        </span>
                      )
                    )}
                  </div>
                ) : (
                  <span className="text-xs text-ink-3">
                    No cipher transforms observed in unencrypted handshake
                    frames (session may have been captured mid-stream).
                  </span>
                )}
              </TableCell>
              <TableCell>
                <EvidenceStateBadge
                  state={evidence_states?.cipher_suites || "UNKNOWN"}
                />
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                Diffie-Hellman / Key Exchange Groups
              </TableCell>
              <TableCell>
                {protocol.observed_dh_groups &&
                protocol.observed_dh_groups.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {protocol.observed_dh_groups.map((dh: string, idx: number) => (
                      <span key={idx} className={chip}>
                        {dh}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-xs text-ink-3">
                    Diffie-Hellman parameters not observed in capture window.
                    State: UNKNOWN.
                  </span>
                )}
              </TableCell>
              <TableCell>
                <EvidenceStateBadge
                  state={evidence_states?.dh_groups || "UNKNOWN"}
                />
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-semibold text-ink">
                Observed IKE Exchange Types
              </TableCell>
              <TableCell>
                {protocol.observed_exchange_types &&
                protocol.observed_exchange_types.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {protocol.observed_exchange_types.map((ex: string, idx: number) => (
                      <span key={idx} className={chip}>
                        {ex}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-xs text-ink-3">
                    No discrete IKE exchange headers detected.
                  </span>
                )}
              </TableCell>
              <TableCell>
                <EvidenceStateBadge
                  state={evidence_states?.exchange_types || "UNKNOWN"}
                />
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </Section>

      <Section
        index="§3"
        title="Session SPI Identifiers"
        description="Security Parameter Indexes observed in the negotiation — copy any value for correlation."
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
          <div className="space-y-2">
            <Subsection title={`Initiator SPIs (${protocol.observed_initiator_spis?.length || 0})`}>
              {protocol.observed_initiator_spis &&
              protocol.observed_initiator_spis.length > 0 ? (
                <Table>
                  <TableHeader>
                    <tr>
                      <TableHead>Security Parameter Index</TableHead>
                    </tr>
                  </TableHeader>
                  <TableBody>
                    {protocol.observed_initiator_spis.map((spi: string, idx: number) => (
                      <TableRow key={idx}>
                        <TableCell mono>
                          <CopyableValue value={spi} label="Initiator SPI" />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState compact title="No initiator SPIs observed." />
              )}
            </Subsection>
          </div>

          <div className="space-y-2">
            <Subsection title={`Responder SPIs (${protocol.observed_responder_spis?.length || 0})`}>
              {protocol.observed_responder_spis &&
              protocol.observed_responder_spis.length > 0 ? (
                <Table>
                  <TableHeader>
                    <tr>
                      <TableHead>Security Parameter Index</TableHead>
                    </tr>
                  </TableHeader>
                  <TableBody>
                    {protocol.observed_responder_spis.map((spi: string, idx: number) => (
                      <TableRow key={idx}>
                        <TableCell mono>
                          <CopyableValue value={spi} label="Responder SPI" />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState compact title="No responder SPIs observed." />
              )}
            </Subsection>
          </div>
        </div>
      </Section>

      <Section
        index="§4"
        title="Raw Dissection Detail"
        description="Full per-record counts and evidence states exactly as produced by the parser."
      >
        <div className="border border-line bg-panel">
          <button
            type="button"
            onClick={() => setShowRawDetail((v) => !v)}
            aria-expanded={showRawDetail}
            className="w-full flex items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-panel-2 transition-colors"
          >
            <span className="text-[13px] font-semibold text-ink">
              Parser record — packet counts, list sizes & evidence states
            </span>
            <ChevronRight
              className={`w-4 h-4 text-ink-3 shrink-0 transition-transform ${
                showRawDetail ? "rotate-90" : ""
              }`}
            />
          </button>

          {showRawDetail && (
            <div className="border-t border-line p-4 space-y-4">
              <div className="border border-line bg-panel-2 font-mono text-xs">
                {[
                  ["ipsec_detected", protocol.ipsec_detected ? "true" : "false"],
                  ["total_packets_inspected", String(protocol.total_packets_inspected)],
                  ["ipsec_packet_count", String((protocol as any).ipsec_packet_count ?? "—")],
                  ["ikev1_packet_count", String(protocol.ikev1_packet_count)],
                  ["ikev2_packet_count", String(protocol.ikev2_packet_count)],
                  ["esp_packet_count", String(protocol.esp_packet_count)],
                  ["ah_packet_count", String(protocol.ah_packet_count)],
                  ["nat_t_detected", protocol.nat_t_detected ? "true" : "false"],
                  [
                    "observed_initiator_spis",
                    String(protocol.observed_initiator_spis?.length ?? 0),
                  ],
                  [
                    "observed_responder_spis",
                    String(protocol.observed_responder_spis?.length ?? 0),
                  ],
                  [
                    "observed_cipher_suites",
                    String(protocol.observed_cipher_suites?.length ?? 0),
                  ],
                  ["observed_dh_groups", String(protocol.observed_dh_groups?.length ?? 0)],
                  [
                    "observed_exchange_types",
                    String(protocol.observed_exchange_types?.length ?? 0),
                  ],
                ].map(([key, value], idx, arr) => (
                  <div
                    key={key}
                    className={`flex justify-between gap-3 px-3 py-1.5 ${
                      idx < arr.length - 1 ? "border-b border-line" : ""
                    }`}
                  >
                    <span className="text-ink-3">{key}</span>
                    <span className="font-semibold text-ink">{value}</span>
                  </div>
                ))}
              </div>

              <Subsection title="Evidence States">
                {evidence_states && Object.keys(evidence_states).length > 0 ? (
                  <div className="border border-line bg-panel-2 font-mono text-xs">
                    {Object.entries(evidence_states).map(([key, state], idx, arr) => (
                      <div
                        key={key}
                        className={`flex items-center justify-between gap-3 px-3 py-1.5 ${
                          idx < arr.length - 1 ? "border-b border-line" : ""
                        }`}
                      >
                        <span className="text-ink-3">{key}</span>
                        <EvidenceStateBadge state={state} />
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    compact
                    title="No evidence states recorded for this run."
                  />
                )}
              </Subsection>
            </div>
          )}
        </div>
      </Section>

      <IkeEvidenceConcordanceSection analysisId={analysisId} protocol={protocol} />
    </div>
  );
}

function IkeEvidenceConcordanceSection({
  analysisId,
  protocol,
}: {
  analysisId: string;
  protocol: any;
}) {
  const { data: concordanceRecords, isLoading: isConcordanceLoading } = useQuery({
    queryKey: ["ikeConcordance", analysisId],
    queryFn: () => api.ikeAssessment.getConcordance(analysisId),
  });

  const { data: ikeStatus } = useQuery({
    queryKey: ["ikeStatus"],
    queryFn: () => api.ikeAssessment.getStatus(),
  });

  const latestConcordance =
    concordanceRecords && concordanceRecords.length > 0 ? concordanceRecords[0] : null;

  const verdictClass = !latestConcordance
    ? "bg-info-bg text-ink-2 border-info-border"
    : latestConcordance.concordance_status === "CONSISTENT"
    ? "bg-positive-bg text-positive border-positive-border"
    : latestConcordance.concordance_status === "CONFLICT"
    ? "bg-critical-bg text-critical border-critical-border"
    : "bg-medium-bg text-medium border-medium-border";

  const laneChip =
    "px-1.5 py-0.5 text-[11px] font-mono bg-panel-3 border border-line text-ink-2";

  const laneRow = "flex justify-between gap-3 text-ink-3";

  return (
    <Section
      index="§5"
      title="Evidence Concordance Lane"
      description="Deterministic triangulation across passive TShark packet captures, bounded active endpoint probes, and lab ground truth."
      actions={
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-ink-3">IKE-scan toolchain:</span>
          {ikeStatus?.ike_scan_available ? (
            <span className="px-2 py-0.5 bg-positive-bg border border-positive-border text-positive font-semibold">
              AVAILABLE ({ikeStatus.ike_scan_version || "OPERABLE"})
            </span>
          ) : (
            <span className="px-2 py-0.5 bg-medium-bg border border-medium-border text-medium font-semibold">
              UNAVAILABLE ON HOST (Live scan disabled)
            </span>
          )}
        </div>
      }
    >
      <div className="border border-line bg-panel p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold">
              Concordance Verdict:
            </span>
            {latestConcordance ? (
              <span
                className={`px-2.5 py-1 text-xs font-mono font-bold border ${verdictClass}`}
              >
                {latestConcordance.concordance_status}
              </span>
            ) : isConcordanceLoading ? (
              <span role="status" aria-live="polite" className="text-[11px] font-mono text-ink-3">
                Evaluating concordance…
              </span>
            ) : (
              <span className="px-2.5 py-1 text-xs font-mono font-bold bg-info-bg border border-info-border text-ink-2">
                INSUFFICIENT EVIDENCE (NO ACTIVE PROBES CONDUCTED FOR THIS CAPTURE)
              </span>
            )}
          </div>

          <div className="text-[11px] font-mono text-ink-3">
            {latestConcordance
              ? `Evaluated: ${new Date(latestConcordance.evaluated_at).toLocaleString()}`
              : "Awaiting authorized active probe triangulation"}
          </div>
        </div>

        {/* 3-Lane Architecture Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3 bg-panel-2 border border-line space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-mono font-semibold text-ink">
                Lane 1: Passive TShark Dissection
              </span>
              <span className={laneChip}>Ground Capture Facts</span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className={laneRow}>
                <span>Observed IKE Versions:</span>
                <span className="font-semibold text-ink">{observedIkeVersions(protocol)}</span>
              </div>
              <div className={laneRow}>
                <span>Negotiated Cipher:</span>
                <span className="font-semibold text-ink">
                  {protocol.observed_cipher_suites?.[0] || "Not Observed in Clear"}
                </span>
              </div>
              <div className={laneRow}>
                <span>Initial Handshake Frames:</span>
                <span className="font-semibold text-ink">
                  {protocol.ikev1_packet_count + protocol.ikev2_packet_count > 0
                    ? "Present"
                    : "Missing / Incomplete"}
                </span>
              </div>
            </div>
            <p className="text-[11px] text-ink-3 pt-1 border-t border-line">
              Passively derived from TShark 4.6.4 without emitting any network traffic.
            </p>
          </div>

          <div className="p-3 bg-panel-2 border border-line space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-mono font-semibold text-ink">
                Lane 2: Active IKE-scan Probe
              </span>
              <span className="px-1.5 py-0.5 text-[11px] font-mono bg-medium-bg border border-medium-border text-medium">
                Scanner Evidence
              </span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className={laneRow}>
                <span>Probe Status:</span>
                <span className="font-semibold text-ink">
                  {latestConcordance?.concordance_details?.active_lane?.response_categories?.[0] ||
                    (ikeStatus?.ike_scan_available ? "NO RECENT RUN" : "TOOL UNAVAILABLE")}
                </span>
              </div>
              <div className={laneRow}>
                <span>Accepted Cipher:</span>
                <span className="font-semibold text-ink">
                  {latestConcordance?.active_accepted_cipher || "None Recorded"}
                </span>
              </div>
              <div className={laneRow}>
                <span>IKEv2 Experimental:</span>
                <span className="font-semibold text-medium">Default Proposal Only</span>
              </div>
            </div>
            <p className="text-[11px] text-ink-3 pt-1 border-t border-line">
              Active probes prove only endpoint response capability, not tunnel
              authentication or security.
            </p>
          </div>

          <div className="p-3 bg-panel-2 border border-line space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-mono font-semibold text-ink">
                Lane 3: Lab Ground Truth
              </span>
              <span className={laneChip}>Namespace Baseline</span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className={laneRow}>
                <span>strongSwan Namespace:</span>
                <span className="font-semibold text-ink">Isolated Testbed</span>
              </div>
              <div className={laneRow}>
                <span>External Traffic:</span>
                <span className="font-semibold text-positive">ZERO (Strictly Blocked)</span>
              </div>
              <div className={laneRow}>
                <span>Credential Cracking:</span>
                <span className="font-semibold text-critical">
                  FORBIDDEN (--pskcrack banned)
                </span>
              </div>
            </div>
            <p className="text-[11px] text-ink-3 pt-1 border-t border-line">
              Controlled environment reference for differential regression testing.
            </p>
          </div>
        </div>

        {/* Epistemic Honesty & Limitation Notice */}
        <div className="p-3 bg-medium-bg border border-medium-border text-[11px] font-mono text-ink-2 space-y-1">
          <div className="font-semibold text-medium flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>Epistemic Boundary &amp; Operational Guardrails</span>
          </div>
          <p>
            1. <strong className="text-ink">Direct Observations Only:</strong>{" "}
            Scanner evidence reflects active probe responses, never asserted
            vulnerabilities or assumed tunnel completion.
          </p>
          <p>
            2. <strong className="text-ink">IKEv2 Experimental Limits:</strong>{" "}
            Upstream{" "}
            <code className="bg-panel px-1 text-accent-ink">ike-scan</code> IKEv2
            implementation sends default proposals and does not comprehensively
            enumerate transforms.
          </p>
          <p>
            3. <strong className="text-ink">Intrusive Probes Prohibited:</strong>{" "}
            Aggressive Mode identity harvesting,{" "}
            <code className="bg-panel px-1 text-critical">--pskcrack</code>, and
            credential guessing are strictly excluded from all adapter execution
            vectors.
          </p>
        </div>
      </div>
    </Section>
  );
}

function observedIkeVersions(protocol: any): string {
  if (protocol.ikev2_packet_count > 0 && protocol.ikev1_packet_count > 0) {
    return "IKEv1, IKEv2";
  }
  if (protocol.ikev2_packet_count > 0) return "IKEv2";
  if (protocol.ikev1_packet_count > 0) return "IKEv1";
  return "None Observed";
}
