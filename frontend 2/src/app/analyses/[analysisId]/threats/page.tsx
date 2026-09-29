"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Section } from "@/components/ui/section";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { SeverityBadge, EvidenceStateBadge } from "@/components/ui/badge";
import { CopyableValue } from "@/components/ui/table";
import { ThreatInstanceDTO, ThreatIntelItemDTO } from "@/lib/api/types";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Hash,
  Database,
  Info,
  ChevronRight,
  FileSearch,
} from "lucide-react";

export default function ThreatMatrixPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const {
    data: threats,
    isLoading: threatsLoading,
    isError: threatsError,
    error: threatsErr,
    refetch: refetchThreats,
  } = useQuery({
    queryKey: ["threats", analysisId],
    queryFn: () => api.analyses.getThreats(analysisId),
  });

  const {
    data: threatIntel,
    isLoading: intelLoading,
  } = useQuery({
    queryKey: ["threat-intelligence", analysisId],
    queryFn: () => api.analyses.getThreatIntelligence(analysisId),
  });

  const isLoading = threatsLoading;

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState
          compact
          title="Mapping threat catalog…"
          description="Correlating findings against the deterministic threat catalog (THR-001..THR-008) and MITRE ATT&CK."
        />
      </div>
    );
  }

  if (threatsError || !threats) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load threat matrix"
          description={(threatsErr as any)?.message || "Unknown error"}
          action={
            <Button variant="secondary" size="sm" onClick={() => refetchThreats()}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  const catalogHash =
    threats.length > 0 && threats[0].catalog_hash ? threats[0].catalog_hash : null;

  const toggleThreat = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold text-ink tracking-tight">
          Threat Matrix
        </h1>
        <p className="text-[13px] text-ink-2">
          Correlated adversary tactics and exploitable vectors mapped from detected
          protocol weaknesses to MITRE ATT&CK techniques.
        </p>
      </header>

      <Section
        index="§1"
        title="Threat Catalog"
        description="Pre-authored threat scenarios (THR-001 through THR-008) triggered by this capture. Expand a row for classification, impact, and provenance."
      >
        <div className="border border-line bg-panel-2 p-3 text-xs text-ink-2 space-y-1.5">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-ink">Epistemic Boundary</span>
              {catalogHash && (
                <span className="flex items-center gap-1.5 font-mono text-[11px] text-ink-3">
                  <Hash className="w-3.5 h-3.5" />
                  <span>Catalog Hash:</span>
                  <CopyableValue value={catalogHash} truncate />
                </span>
              )}
            </div>
          </div>
          <p className="leading-relaxed">
            <strong className="text-ink">MITRE ATT&CK mappings represent taxonomy context for operational risk prioritization.</strong>{" "}
            They are{" "}
            <strong className="text-ink">NOT</strong>{" "}
            assertions that an adversary executed a technique or that a gateway is
            compromised. Unmapped entries reflect cryptanalytic boundaries rather
            than execution techniques.
          </p>
        </div>

        {threats.length > 0 ? (
          <div className="space-y-2">
            {threats.map((threat) => {
              const attackId =
                threat.mitre_attack_id ||
                (threat.mitre_technique_id !== "N/A"
                  ? threat.mitre_technique_id
                  : null);
              const isExpanded = expanded.has(threat.threat_id);
              return (
                <div
                  key={threat.threat_id}
                  className="border border-line bg-panel"
                >
                  <button
                    type="button"
                    onClick={() => toggleThreat(threat.threat_id)}
                    aria-expanded={isExpanded}
                    className="w-full flex items-start justify-between gap-3 p-3.5 text-left hover:bg-panel-2 transition-colors"
                  >
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <SeverityBadge severity={threat.risk_tier} />
                        <span className="font-mono text-[11px] text-ink-3">
                          {threat.threat_id}
                        </span>
                        <span className="text-[13px] font-semibold text-ink">
                          {threat.threat_name || threat.title}
                        </span>
                      </div>
                      <p className="text-xs text-ink-3 font-mono">
                        {threat.attack_vector || threat.category} · Likelihood{" "}
                        {threat.likelihood} · Impact {threat.impact}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {attackId && (
                        <span className="font-mono text-xs text-accent-ink font-semibold">
                          {attackId}
                        </span>
                      )}
                      <ChevronRight
                        className={`w-4 h-4 text-ink-3 transition-transform ${
                          isExpanded ? "rotate-90" : ""
                        }`}
                      />
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="border-t border-line px-3.5 py-3 space-y-3">
                      <div>
                        <h4 className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold mb-1">
                          Why this matters
                        </h4>
                        {threat.mitre_attack_id && threat.mitre_attack_rationale ? (
                          <p className="text-xs text-ink-2 leading-relaxed">
                            {threat.mitre_attack_rationale}
                          </p>
                        ) : (
                          <p className="text-xs text-ink-2 leading-relaxed">
                            This threat scenario represents a mathematical or
                            cryptanalytic limitation (e.g. Diffie-Hellman prime
                            modulus precomputation or 64-bit block collision
                            birthday bound) rather than an adversary execution
                            technique in MITRE ATT&CK Enterprise.
                          </p>
                        )}
                      </div>

                      <div>
                        <h4 className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold mb-1">
                          Classification
                        </h4>
                        <div className="border border-line bg-panel-2 font-mono text-xs">
                          <div className="flex justify-between gap-3 px-2.5 py-1.5 border-b border-line">
                            <span className="text-ink-3">Likelihood</span>
                            <span className="font-semibold text-ink">
                              {threat.likelihood}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3 px-2.5 py-1.5 border-b border-line">
                            <span className="text-ink-3">Impact</span>
                            <span className="font-semibold text-ink">
                              {threat.impact}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3 px-2.5 py-1.5 border-b border-line">
                            <span className="text-ink-3">Risk Tier</span>
                            <SeverityBadge severity={threat.risk_tier} />
                          </div>
                          <div className="flex justify-between gap-3 px-2.5 py-1.5">
                            <span className="text-ink-3">Evidence State</span>
                            <EvidenceStateBadge
                              state={threat.evidence_state || "VERIFIED"}
                            />
                          </div>
                        </div>
                      </div>

                      <div>
                        <h4 className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold mb-1">
                          MITRE ATT&CK Mapping
                        </h4>
                        {threat.mitre_attack_id ? (
                          <div className="border border-line bg-panel-2 p-2.5 space-y-1.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-sm font-bold text-accent-ink">
                                {threat.mitre_attack_id}
                              </span>
                              {threat.mitre_attack_url && (
                                <a
                                  href={threat.mitre_attack_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-accent-ink hover:underline flex items-center gap-1 text-[11px] font-mono"
                                >
                                  <span>Official Docs</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              )}
                            </div>
                            {threat.mitre_attack_name && (
                              <div className="text-[13px] font-semibold text-ink">
                                {threat.mitre_attack_name}
                              </div>
                            )}
                          </div>
                        ) : (
                          <p className="text-xs text-ink-3 italic">
                            Unmapped — cryptanalytic boundary, not an execution
                            technique.
                          </p>
                        )}
                      </div>

                      <div>
                        <h4 className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold mb-1">
                          Policy Reference
                        </h4>
                        <div className="border border-line bg-panel-2 font-mono text-xs">
                          <div className="flex justify-between gap-3 px-2.5 py-1.5 border-b border-line">
                            <span className="text-ink-3">NIST Control</span>
                            <span className="font-semibold text-ink">
                              {threat.nist_control || "N/A"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3 px-2.5 py-1.5 items-center">
                            <span className="text-ink-3">Catalog Hash</span>
                            {catalogHash ? (
                              <CopyableValue value={catalogHash} truncate />
                            ) : (
                              <span className="text-ink-3">N/A</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {threat.finding_id && (
                        <div>
                          <h4 className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold mb-1">
                            Related Finding
                          </h4>
                          <Link
                            href={`/analyses/${analysisId}/evidence?findingId=${threat.finding_id}`}
                            className="inline-flex items-center gap-1 text-[13px] font-medium text-accent-ink hover:underline"
                          >
                            <FileSearch className="w-3.5 h-3.5" />
                            <span>
                              View evidence DAG for {threat.finding_id}
                            </span>
                          </Link>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <EmptyState
            icon={<CheckCircle2 />}
            title="No active threat mappings for current capture"
            description="No policy violations were triggered on the evaluated packet evidence. MITRE ATT&CK adversary tactics are mapped strictly from verified security findings. Zero findings indicates that no prohibited transforms or protocol anomalies were observed in this capture — it is not an assertion of overall infrastructure invulnerability."
          />
        )}
      </Section>

      {threatIntel && (
        <Section
          index="§2"
          title="Global Threat Intelligence Snapshot"
          description="Dated reference snapshot of known IPsec vulnerabilities from CISA KEV and FIRST EPSS — not matched to this capture."
        >
          <div className="border border-line bg-panel-2 p-3 text-xs text-ink-2 space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-ink">
              <Info className="w-3.5 h-3.5 text-ink-3 shrink-0" />
              <span>Reference context · Not matched to observed capture</span>
            </div>
            <p className="leading-relaxed">
              The CVE records below represent a dated reference snapshot of known
              IPsec vulnerabilities from CISA KEV and FIRST EPSS for analyst
              situational awareness.{" "}
              <strong className="text-ink">
                None of these CVEs have been matched to an observed product,
                vendor, or version in this packet capture.
              </strong>
            </p>
          </div>

          <div className="flex items-center justify-between gap-3 text-xs font-mono text-ink-3 border-b border-line pb-2 flex-wrap">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-accent" />
              <span>Source Status:</span>
              <span className="font-bold text-ink">
                {threatIntel.source_freshness}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-ink-3" />
              <span>Offline Verified Snapshot</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {threatIntel.intel_items.map((item: ThreatIntelItemDTO) => (
              <div
                key={item.cve_id}
                className="p-3 bg-panel border border-line text-xs space-y-2"
              >
                <div className="flex items-center justify-between border-b border-line pb-1.5 gap-2">
                  <span className="font-bold text-ink font-mono">{item.cve_id}</span>
                  <span
                    className={`px-1.5 py-0.5 text-[11px] uppercase font-bold border ${
                      item.cisa_kev_status === "PRESENT"
                        ? "bg-critical-bg text-critical border-critical-border"
                        : "bg-panel-2 text-ink-3 border-line"
                    }`}
                  >
                    KEV: {item.cisa_kev_status}
                  </span>
                </div>

                {item.cisa_kev_record && (
                  <div className="space-y-1 text-[11px]">
                    <div className="text-ink-3 font-semibold">
                      {item.cisa_kev_record.product}
                    </div>
                    <div className="text-ink-2 leading-tight line-clamp-2">
                      {item.cisa_kev_record.short_description}
                    </div>
                    <div className="text-[11px] text-ink-3">
                      Date Added: {item.cisa_kev_record.date_added}
                    </div>
                  </div>
                )}

                {item.epss_record && (
                  <div className="pt-1.5 border-t border-line flex justify-between gap-3 text-[11px]">
                    <span className="text-ink-3">FIRST EPSS (30-day):</span>
                    <span className="font-bold text-ink">
                      {(item.epss_record.epss_score * 100).toFixed(1)}% (
                      {(item.epss_record.epss_percentile * 100).toFixed(0)}th
                      percentile)
                    </span>
                  </div>
                )}
              </div>
            ))}
          </div>

          <p className="text-[11px] text-ink-3 italic">
            Notice: {threatIntel.disclaimer}
          </p>
        </Section>
      )}
    </div>
  );
}
