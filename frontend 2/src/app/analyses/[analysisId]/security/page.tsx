"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { useAnalysis } from "@/lib/analysis-context";
import { Section } from "@/components/ui/section";
import { EmptyState } from "@/components/ui/empty-state";
import { Button, ButtonLink } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge, EvidenceStateBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { SecurityFindingDTO } from "@/lib/api/types";
import { formatCoverage } from "@/lib/format";
import { SocWorkflowBanner } from "@/components/soc/soc-workflow-banner";
import {
  Search,
  FileSearch,
  FileText,
  History,
  Radio,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Hash,
  Activity,
  Layers,
} from "lucide-react";

function getFindingSource(f: SecurityFindingDTO) {
  const rid = (f.rule_id || "").toUpperCase();
  if (rid.includes("OPENVAS") || rid.includes("GREENBONE") || rid.includes("CVE")) {
    return {
      label: "SCANNER (SUPPLEMENTAL)",
      badge: "border-info-border bg-info-bg text-info",
      description:
        "Supplemental scanner observation imported via Greenbone/OpenVAS XML. Does not calculate core score deductions.",
    };
  }
  if (rid.includes("CONF") || rid.includes("CERT") || rid.includes("DRIFT")) {
    return {
      label: "CONFIG INVENTORY",
      badge: "border-info-border bg-info-bg text-info",
      description:
        "Configuration or certificate baseline drift finding from strongSwan inventory.",
    };
  }
  if (rid.includes("THREAT") || rid.includes("ATTACK") || rid.includes("MITRE")) {
    return {
      label: "THREAT INTEL",
      badge: "border-medium-border bg-medium-bg text-medium",
      description: "Contextual STRIDE / MITRE ATT&CK tactical mapping.",
    };
  }
  return {
    label: "DETERMINISTIC POLICY",
    badge: "border-positive-border bg-positive-bg text-positive",
    description:
      "Evaluated deterministically from versioned YAML policy bundle (NIST SP 800-77 / RFC 8221).",
  };
}

function riskTierBadgeClass(tier: string): string {
  switch (tier) {
    case "CRITICAL":
      return "bg-critical-bg text-critical border-critical-border";
    case "HIGH":
      return "bg-high-bg text-high border-high-border";
    case "MEDIUM":
      return "bg-medium-bg text-medium border-medium-border";
    case "LOW":
    case "NO_FINDINGS_UNDER_THIS_POLICY":
      return "bg-positive-bg text-positive border-positive-border";
    case "INSUFFICIENT_EVIDENCE":
      return "bg-info-bg text-info border-info-border";
    default:
      return "bg-panel-2 text-ink-2 border-line";
  }
}

export default function SecurityAssessmentPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const { overview } = useAnalysis();
  const [selectedFinding, setSelectedFinding] = useState<SecurityFindingDTO | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");

  const {
    data: findings,
    isLoading: findingsLoading,
    isError: findingsError,
    error: findingsErr,
    refetch: refetchFindings,
  } = useQuery({
    queryKey: ["findings", analysisId],
    queryFn: () => api.analyses.getFindings(analysisId),
  });

  const {
    data: riskAssessment,
    isLoading: riskLoading,
  } = useQuery({
    queryKey: ["risk", analysisId],
    queryFn: () => api.analyses.getRisk(analysisId),
  });

  const isLoading = findingsLoading || riskLoading;

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState
          compact
          title="Evaluating cryptographic policies…"
          description="Calculating score deductions and compiling findings."
        />
      </div>
    );
  }

  if (findingsError || !findings) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load security findings"
          description={(findingsErr as any)?.message || "Unknown error"}
          action={
            <Button variant="secondary" size="sm" onClick={() => refetchFindings()}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  const filteredFindings = (findings || []).filter((f) => {
    const matchesSeverity =
      severityFilter === "ALL" || f.severity.toUpperCase() === severityFilter;
    const matchesSearch =
      search === "" ||
      (f.title || "").toLowerCase().includes(search.toLowerCase()) ||
      (f.rule_id || "").toLowerCase().includes(search.toLowerCase()) ||
      (f.affected_entity || "").toLowerCase().includes(search.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  // Find matching risk item for selected finding
  const selectedRiskItem = selectedFinding && riskAssessment?.items
    ? riskAssessment.items.find((item) => item.finding_id === selectedFinding.finding_id)
    : null;

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold text-ink tracking-tight">
          Security Assessment
        </h1>
        <p className="text-[13px] text-ink-2">
          Deterministic policy findings, score deductions, and remediation
          directives evaluated against NIST SP 800-77 Rev 1 and RFC 8221 rules.
        </p>
      </header>

      <SocWorkflowBanner
        activeStep={4}
        analysisId={analysisId}
        evidenceCoverage={riskAssessment?.evidence_coverage ?? null}
      />

      {riskAssessment && (
        <Section
          index="§1"
          title="Risk Posture"
          description="Aggregate risk tier and evidence coverage for the active policy bundle."
        >
          <div className="border border-line bg-panel">
            <div className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-line">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3">
                  Aggregate Risk Posture
                </span>
                <span
                  className={`px-2 py-0.5 text-xs font-mono font-bold uppercase border inline-flex items-center gap-1 ${riskTierBadgeClass(
                    riskAssessment.overall_risk_tier
                  )}`}
                >
                  {riskAssessment.overall_risk_tier ===
                  "NO_FINDINGS_UNDER_THIS_POLICY" ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>NO FINDINGS UNDER ACTIVE POLICY</span>
                    </>
                  ) : riskAssessment.overall_risk_tier === "INSUFFICIENT_EVIDENCE" ? (
                    <>
                      <HelpCircle className="w-3.5 h-3.5" />
                      <span>INSUFFICIENT EVIDENCE (GAPS OBSERVED)</span>
                    </>
                  ) : (
                    riskAssessment.overall_risk_tier
                  )}
                </span>
              </div>

              <div className="flex items-center gap-4 font-mono text-xs text-ink-2">
                <div className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-accent" />
                  <span>Evidence Coverage:</span>
                  <span className="font-bold text-ink">
                    {formatCoverage(riskAssessment.evidence_coverage)}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-ink-3" />
                  <span>Gaps:</span>
                  <span className="font-bold text-ink">
                    {riskAssessment.evidence_gaps_count ?? 0}
                  </span>
                </div>
              </div>
            </div>

            {overview?.security_posture && (
              <div className="p-4 border-b border-line flex flex-col sm:flex-row sm:items-center gap-4">
                <div className="flex-1 min-w-0">
                  <ScoreDisplay
                    score={overview.security_posture.score}
                    coverage={overview.security_posture.evidence_coverage}
                    riskTier={overview.security_posture.aggregate_risk_tier}
                    status={overview.security_posture.status}
                    size="md"
                    showCoverage
                  />
                </div>
                <p className="text-xs text-ink-3 max-w-xs leading-relaxed">
                  Posture score derived from the itemized deductions below.
                  Evaluated on observable packet evidence only.
                </p>
              </div>
            )}

            <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono text-ink-3">
              <div>
                <span>Methodology:</span>{" "}
                <span className="text-ink-2 font-semibold">
                  {riskAssessment.methodology_type ||
                    "DETERMINISTIC_PRIORITIZATION_HEURISTIC"}
                </span>{" "}
                <span>
                  ({riskAssessment.risk_policy_id} v
                  {riskAssessment.risk_policy_version})
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <Hash className="w-3 h-3 text-ink-3" />
                <span>Policy Hash:</span>
                <CopyableValue value={riskAssessment.risk_policy_hash} truncate />
              </div>
            </div>

            <div className="px-4 pb-3">
              <p className="text-[11px] text-ink-3 italic">
                Notice:{" "}
                {riskAssessment.disclaimer ||
                  "Internal deterministic heuristic. Not an empirically calibrated probability."}
              </p>
            </div>
          </div>
        </Section>
      )}

      <Section
        index="§2"
        title={`Findings (${filteredFindings.length})`}
        description="Deterministic policy violations with score deductions. Select a row for full forensic detail."
      >
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex-1 max-w-md">
            <div className="relative">
              <Search className="w-4 h-4 text-ink-3 absolute left-2.5 top-2 pointer-events-none" />
              <Input
                type="text"
                placeholder="Search findings by rule ID, title, or entity..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 font-mono"
                aria-label="Search findings by rule ID, title, or entity"
              />
            </div>
          </div>

          <div
            className="flex items-center gap-1 font-mono text-xs overflow-x-auto"
            role="group"
            aria-label="Filter by severity"
          >
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                aria-pressed={severityFilter === sev}
                className={`px-3 h-8 border transition-colors ${
                  severityFilter === sev
                    ? "bg-accent-press text-on-accent border-accent-border font-semibold"
                    : "bg-panel text-ink-2 border-line hover:border-line-strong hover:text-ink"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          <div className={selectedFinding ? "lg:col-span-7" : "lg:col-span-12"}>
            {filteredFindings.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Severity</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Rule ID</TableHead>
                    <TableHead>Finding Title</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Affected Entity</TableHead>
                    <TableHead>Deduction</TableHead>
                    <TableHead>Evidence</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {filteredFindings.map((finding) => {
                    const src = getFindingSource(finding);
                    return (
                      <TableRow
                        key={finding.finding_id}
                        onClick={() => setSelectedFinding(finding)}
                        isSelected={selectedFinding?.finding_id === finding.finding_id}
                      >
                        <TableCell>
                          <SeverityBadge severity={finding.severity} />
                        </TableCell>
                        <TableCell>
                          <span
                            className={`px-1.5 py-0.5 text-[11px] font-mono font-bold uppercase border ${src.badge}`}
                          >
                            {src.label}
                          </span>
                        </TableCell>
                        <TableCell mono>
                          <span className="font-semibold text-ink">
                            {finding.rule_id}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="font-semibold text-ink">
                            {finding.title}
                          </span>
                        </TableCell>
                        <TableCell mono className="text-ink-3 uppercase text-[11px]">
                          {finding.category}
                        </TableCell>
                        <TableCell mono className="text-ink-2 text-[11px]">
                          {finding.affected_entity}
                        </TableCell>
                        <TableCell mono>
                          <span className="font-bold text-critical">
                            -{finding.score_deduction}
                          </span>
                        </TableCell>
                        <TableCell>
                          <EvidenceStateBadge state={finding.evidence_state} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                icon={<Search />}
                title="No security findings match the current filter"
                description={
                  riskAssessment?.overall_risk_tier === "INSUFFICIENT_EVIDENCE"
                    ? `Evidence coverage (${formatCoverage(
                        riskAssessment.evidence_coverage
                      )}) is below policy threshold. Inadequate evidence is preserved as an explicit gap, not assumed safe.`
                    : riskAssessment?.overall_risk_tier ===
                      "NO_FINDINGS_UNDER_THIS_POLICY"
                    ? `Zero rule violations identified with ${formatCoverage(
                        riskAssessment.evidence_coverage
                      )} evaluated evidence coverage.`
                    : "Adjust the severity filter or search query to broaden the result set."
                }
              />
            )}
          </div>

          {selectedFinding && (
            <div className="lg:col-span-5">
              <InspectorDrawer
                isOpen={!!selectedFinding}
                onClose={() => setSelectedFinding(null)}
                title={selectedFinding.title}
                subtitle={`Rule: ${selectedFinding.rule_id}`}
                badge={<SeverityBadge severity={selectedFinding.severity} />}
                actions={
                  <div className="flex items-center gap-2">
                    <ButtonLink
                      href={`/analyses/${analysisId}/evidence?findingId=${selectedFinding.finding_id}`}
                      variant="primary"
                      size="sm"
                    >
                      <FileSearch className="w-3.5 h-3.5" />
                      <span>Evidence DAG</span>
                    </ButtonLink>
                    <ButtonLink
                      href={`/analyses/${analysisId}/reports`}
                      variant="secondary"
                      size="sm"
                    >
                      <FileText className="w-3.5 h-3.5" />
                      <span>Report</span>
                    </ButtonLink>
                  </div>
                }
              >
                <div className="space-y-4">
                  {(() => {
                    const src = getFindingSource(selectedFinding);
                    return (
                      <div className="p-3 bg-panel-2 border border-line space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-ink-3 text-[11px] uppercase tracking-wide font-semibold">
                            Provenance Source
                          </span>
                          <span
                            className={`px-1.5 py-0.5 text-[11px] font-mono font-bold uppercase border ${src.badge}`}
                          >
                            {src.label}
                          </span>
                        </div>
                        <p className="text-xs text-ink-2">{src.description}</p>
                      </div>
                    );
                  })()}

                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-3 bg-critical-bg border border-critical-border font-mono text-xs space-y-0.5">
                      <span className="text-ink-3 block text-[11px] uppercase tracking-wide">
                        Score Deduction
                      </span>
                      <span className="font-bold text-critical text-sm">
                        -{selectedFinding.score_deduction} Points
                      </span>
                    </div>
                    <div className="p-3 bg-panel-2 border border-line font-mono text-xs space-y-0.5">
                      <span className="text-ink-3 block text-[11px] uppercase tracking-wide">
                        Realized Risk Tier
                      </span>
                      <span className="font-bold text-ink text-sm">
                        {selectedRiskItem?.risk_tier || selectedFinding.severity}
                      </span>
                    </div>
                  </div>

                  {selectedRiskItem &&
                    selectedRiskItem.factors &&
                    selectedRiskItem.factors.length > 0 && (
                      <div>
                        <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1.5 font-semibold">
                          Deterministic Risk Factor Breakdown
                        </span>
                        <Table>
                          <TableHeader>
                            <tr>
                              <TableHead>Factor</TableHead>
                              <TableHead>Value</TableHead>
                              <TableHead>Role</TableHead>
                            </tr>
                          </TableHeader>
                          <TableBody>
                            {selectedRiskItem.factors.map((f, idx) => (
                              <TableRow key={idx}>
                                <TableCell mono className="font-semibold text-ink-2">
                                  {f.factor_name}
                                </TableCell>
                                <TableCell mono>
                                  <span
                                    className={`px-1.5 py-0.5 text-[11px] border ${
                                      f.factor_value === "NOT_ASSESSED"
                                        ? "bg-panel-3 text-ink-3 border-line"
                                        : "bg-panel-2 text-ink border-line font-semibold"
                                    }`}
                                  >
                                    {f.factor_value}
                                  </span>
                                </TableCell>
                                <TableCell mono className="text-[11px] text-ink-3">
                                  {f.aggregation_role}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    )}

                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1 font-semibold">
                      Technical Forensics Description
                    </span>
                    <div className="p-3 bg-panel-2 border border-line text-[13px] text-ink-2 leading-relaxed">
                      {selectedFinding.technical_description}
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1 font-semibold">
                      Deterministic Remediation Directive
                    </span>
                    <div className="p-3 bg-panel-2 border border-line text-xs font-mono text-ink leading-relaxed whitespace-pre-wrap">
                      {selectedFinding.remediation_guidance}
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1 font-semibold">
                      Target Entity & Forensic Lineage
                    </span>
                    <div className="space-y-1 font-mono text-xs bg-panel-2 p-3 border border-line">
                      <div className="flex justify-between gap-3">
                        <span className="text-ink-3">Affected Entity:</span>
                        <span className="font-semibold text-ink">
                          {selectedFinding.affected_entity}
                        </span>
                      </div>
                      <div className="flex justify-between gap-3">
                        <span className="text-ink-3">Evidence State:</span>
                        <span className="text-ink-2">
                          {selectedFinding.evidence_state}
                        </span>
                      </div>
                      <div className="flex justify-between gap-3">
                        <span className="text-ink-3">Root Cause Key:</span>
                        <span className="text-ink-2">
                          {selectedFinding.root_cause_key}
                        </span>
                      </div>
                      {selectedRiskItem && (
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">
                            Aggregate Contribution:
                          </span>
                          <span className="font-semibold text-ink-2">
                            {selectedRiskItem.aggregation_role}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-line space-y-2">
                    <span className="text-[11px] text-ink-3 uppercase tracking-wide font-semibold block">
                      SOC Analyst Workflow Transitions
                    </span>
                    <div className="grid grid-cols-2 gap-2">
                      <ButtonLink
                        href={`/analyses/${analysisId}/evidence?view=replay`}
                        variant="secondary"
                        size="sm"
                      >
                        <History className="w-3.5 h-3.5 text-low" />
                        <span>Replay Lineage</span>
                      </ButtonLink>
                      <ButtonLink
                        href="/monitoring"
                        variant="secondary"
                        size="sm"
                      >
                        <Radio className="w-3.5 h-3.5 text-accent" />
                        <span>Fleet Telemetry</span>
                      </ButtonLink>
                    </div>
                  </div>
                </div>
              </InspectorDrawer>
            </div>
          )}
        </div>
      </Section>
    </div>
  );
}
