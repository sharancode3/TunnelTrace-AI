"use client";

import React, { use } from "react";
import Link from "next/link";
import { useAnalysis } from "@/lib/analysis-context";
import { Section, Subsection } from "@/components/ui/section";
import { Stat, StatGrid } from "@/components/ui/stat";
import { EmptyState } from "@/components/ui/empty-state";
import { SeverityBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
import { Tally } from "@/components/ui/tally";
import { Button } from "@/components/ui/button";
import { EChartWrapper } from "@/components/charts/echart-wrapper";
import { useChartMode, getChartPalette } from "@/components/charts/chart-theme";
import * as echarts from "echarts";
import { formatCoverage } from "@/lib/format";
import { AlertTriangle, CheckCircle2, ChevronRight } from "lucide-react";

export default function OverviewPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const { overview, isLoading, isError, analysis, refetch } = useAnalysis();
  const chartMode = useChartMode();

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState compact title="Loading analysis overview…" />
      </div>
    );
  }

  if (isError || !overview) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title={`Unable to load command center for run ${analysisId}`}
          description="The analysis may still be initializing or experienced a pipeline failure. Check the pipeline status above."
          action={
            <Button variant="secondary" size="sm" onClick={refetch}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  const {
    security_posture,
    compliance_counts,
    findings_summary,
    traffic_summary,
    fingerprintability,
    protocol_summary,
  } = overview;

  // Robust Deduction Chart Parsing (supports both object dict and {audit: [...]} array)
  const rawDeductions = security_posture.itemized_deductions;
  let deductionCategories: string[] = [];
  let deductionValues: number[] = [];

  if (rawDeductions && Array.isArray((rawDeductions as any).audit)) {
    deductionCategories = (rawDeductions as any).audit.map(
      (d: any) => d.rule_id || d.finding_id || d.category || "Rule"
    );
    deductionValues = (rawDeductions as any).audit.map(
      (d: any) => Number(d.applied_deduction ?? d.raw_deduction ?? 0)
    );
  } else if (rawDeductions && typeof rawDeductions === "object") {
    deductionCategories = Object.keys(rawDeductions).filter((k) => k !== "total_deduction");
    deductionValues = deductionCategories.map((k) => Number((rawDeductions as any)[k]) || 0);
  }

  const isDemoOrSeeded = Boolean(
    analysis?.is_synthetic_demo ||
    overview?.analysis?.is_synthetic_demo ||
    overview?.capture?.filename === "ikev2_perimeter_audit.pcap" ||
    (protocol_summary?.total_observations === 0 && (findings_summary?.total || 0) > 0)
  );

  const affectedAreas = Array.from(
    (findings_summary.top_findings || []).reduce((acc, f) => {
      const area = f.category || "General";
      acc.set(area, (acc.get(area) || 0) + 1);
      return acc;
    }, new Map<string, number>())
  );

  const mlInferenceInactive =
    traffic_summary.ml_run_status === "NOT_CONFIGURED" ||
    traffic_summary.classified_flows === 0;

  const chartPalette = getChartPalette(chartMode);

  const coveragePct =
    security_posture.evidence_coverage === null ||
    security_posture.evidence_coverage === undefined
      ? null
      : security_posture.evidence_coverage <= 1.0
      ? security_posture.evidence_coverage * 100
      : security_posture.evidence_coverage;

  const deductionChartOptions: echarts.EChartsOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { top: 20, right: 20, bottom: 30, left: 80 },
    xAxis: {
      type: "value",
      axisLabel: { color: chartPalette.axis, fontSize: 10 },
      splitLine: { lineStyle: { color: chartPalette.splitLine, type: "dashed" } },
    },
    yAxis: {
      type: "category",
      data: deductionCategories.length > 0 ? deductionCategories : ["None"],
      axisLabel: { color: chartPalette.axis, fontSize: 10 },
    },
    series: [
      {
        name: "Score Deduction",
        type: "bar",
        data: deductionValues.length > 0 ? deductionValues : [0],
        itemStyle: { color: chartPalette.series },
      },
    ],
  };

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold text-ink tracking-tight">
          Investigation Overview
        </h1>
        <p className="text-[13px] text-ink-2">
          Security posture, material findings, and affected areas for this capture.
        </p>
      </header>

      {isDemoOrSeeded && (
        <div
          className="p-3.5 bg-medium-bg border border-medium-border text-xs space-y-1"
          role="note"
        >
          <div className="flex items-center gap-2 font-semibold text-medium">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Demonstration fixture reference data</span>
          </div>
          <p className="text-[13px] text-ink-2 leading-relaxed">
            This analysis run contains seeded reference demonstration findings and
            posture scores. Wire packet observations were not parsed from a raw PCAP
            stream for this fixture. For empirical wire analysis with
            live-reconstructed IKE/ESP sessions, please ingest verified samples like{" "}
            <code className="font-mono text-xs bg-panel-2 px-1 py-0.5">
              real_tunnel_gcm.pcapng
            </code>{" "}
            or upload an authorized capture.
          </p>
        </div>
      )}

      {!isDemoOrSeeded &&
        (security_posture.score === null ||
          (security_posture as any).status === "NOT_ASSESSABLE" ||
          (security_posture as any).status === "INSUFFICIENT_EVIDENCE" ||
          (security_posture.evidence_coverage !== undefined &&
            security_posture.evidence_coverage < 0.5)) && (
          <div
            className="p-3.5 bg-medium-bg border border-medium-border text-xs space-y-1"
            role="note"
          >
            <div className="flex items-center gap-2 font-semibold text-medium">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                Limited protocol evidence — posture score withheld (
                {formatCoverage(security_posture.evidence_coverage)} coverage)
              </span>
            </div>
            <p className="text-[13px] text-ink-2 leading-relaxed">
              {security_posture.evidence_coverage === 0
                ? "No observable IPsec packet evidence (IKE handshake or ESP traffic) was found in this capture artifact. All policy rules are marked UNKNOWN."
                : `This capture contains partial data plane traffic without the initial IKE key negotiation handshake (${compliance_counts.unknown} check(s) remain UNKNOWN). TunnelTrace AI strictly enforces epistemic honesty: an authoritative 100/100 score is withheld until complete handshake evidence is observed.`}
            </p>
          </div>
        )}

      <Section
        index="§1"
        title="Security Posture"
        description="Posture score evaluated on observable packet evidence — not a formal security certification."
      >
        <div className="border border-line bg-panel">
          <div className="p-4 flex flex-col md:flex-row md:items-center gap-4 border-b border-line">
            <div className="flex-1 min-w-0">
              <ScoreDisplay
                score={security_posture.score}
                coverage={security_posture.evidence_coverage}
                riskTier={security_posture.aggregate_risk_tier}
                status={(security_posture as any).status}
                size="lg"
                showCoverage
              />
            </div>
            <div className="text-[11px] font-mono text-ink-3 space-y-0.5 shrink-0">
              <div>
                Methodology:{" "}
                <span className="text-ink-2 font-semibold">
                  {security_posture.methodology_version || "INTERNAL v1"}
                </span>
              </div>
              <div>
                Risk tier:{" "}
                <span className="text-ink font-semibold">
                  {security_posture.aggregate_risk_tier}
                </span>
              </div>
            </div>
          </div>
          <div className="p-4">
            <StatGrid>
              <Stat
                label="Evidence Coverage"
                value={
                  <Tally
                    value={coveragePct}
                    decimals={1}
                    suffix="%"
                    delay={140}
                  />
                }
                hint="required facts verified"
              />
              <Stat
                label="Unknown Rules"
                value={<Tally value={compliance_counts.unknown} delay={200} />}
                tone="medium"
                hint="not assessable from capture"
              />
              <Stat
                label="Findings"
                value={<Tally value={findings_summary.total} delay={260} />}
                tone={
                  findings_summary.critical > 0
                    ? "critical"
                    : findings_summary.high > 0
                    ? "high"
                    : "default"
                }
                hint={`${findings_summary.critical} critical · ${findings_summary.high} high · ${findings_summary.medium} medium`}
              />
              <Stat
                label="Policy Checks"
                value={
                  <>
                    <Tally
                      value={compliance_counts.pass}
                      suffix=" pass"
                      delay={320}
                    />
                    {" · "}
                    <Tally
                      value={compliance_counts.fail}
                      suffix=" fail"
                      delay={320}
                    />
                  </>
                }
                tone={compliance_counts.fail > 0 ? "critical" : "default"}
                hint={`${compliance_counts.unknown} unknown`}
              />
            </StatGrid>
          </div>
        </div>
      </Section>

      <Section
        index="§2"
        title="Attention Required"
        description="Material findings ranked by score impact. Remediation directives for each finding are on the security assessment page."
        actions={
          <Link
            href={`/analyses/${analysisId}/security`}
            className="inline-flex items-center gap-1 text-[13px] font-medium text-accent-ink hover:underline"
          >
            <span>All findings</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </Link>
        }
      >
        {affectedAreas.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
            <span className="uppercase tracking-wide text-ink-3">
              Affected areas
            </span>
            {affectedAreas.map(([area, count]) => (
              <span
                key={area}
                className="px-1.5 py-0.5 bg-panel-2 border border-line text-ink-2"
              >
                {area} · {count}
              </span>
            ))}
          </div>
        )}

        {findings_summary.top_findings &&
        findings_summary.top_findings.length > 0 ? (
          <div className="border border-line bg-panel divide-y divide-line">
            {findings_summary.top_findings.map((f) => (
              <div
                key={f.finding_id}
                className="p-3.5 flex items-start justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-[11px] text-ink-3">
                      {f.rule_id}
                    </span>
                    <span className="text-[13px] font-semibold text-ink">
                      {f.title}
                    </span>
                  </div>
                  <p className="text-xs text-ink-3 font-mono">
                    Target: {f.affected_entity} · Evidence: {f.evidence_state}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <span className="font-mono text-sm font-bold text-critical">
                    -{f.score_deduction}
                  </span>
                  <span className="block text-[11px] font-mono text-ink-3 uppercase">
                    pts
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={<CheckCircle2 />}
            title="No high or critical findings"
            description="No high or critical severity security findings recorded for this capture."
          />
        )}

        {findings_summary.top_findings &&
          findings_summary.top_findings.length > 0 && (
            <div className="border border-line bg-panel-2 p-3.5 space-y-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3">
                Immediate action — top finding
              </span>
              <p className="text-[13px] font-semibold text-ink">
                {findings_summary.top_findings[0].title}
              </p>
              <p className="text-xs text-ink-2 font-mono whitespace-pre-wrap leading-relaxed">
                {findings_summary.top_findings[0].remediation_guidance}
              </p>
            </div>
          )}
      </Section>

      <Section
        index="§3"
        title="Score Deduction Breakdown"
        description="Itemized point deductions grouped by rule category."
      >
        {deductionCategories.length > 0 ? (
          <div className="border border-line bg-panel p-4">
            <EChartWrapper
              options={deductionChartOptions}
              theme={chartMode}
              height="220px"
              accessibleSummary="Bar chart showing score point deductions grouped by category"
            />
          </div>
        ) : (
          <EmptyState
            compact
            title="Zero score deductions recorded for this analysis."
          />
        )}
      </Section>

      <Section
        index="§4"
        title="Protocol & Traffic Snapshot"
        description="Protocol discovery, encrypted traffic inference, and metadata fingerprintability for this capture."
      >
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="border border-line bg-panel p-4">
            <Subsection title="Protocol Discovery">
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">IPsec Present</span>
                  <span className="font-semibold text-ink">
                    {protocol_summary.total_observations > 0 ? "YES" : "NO"}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">IKE Versions</span>
                  <span className="font-semibold text-ink">
                    {protocol_summary.ike_versions?.join(", ") || "UNKNOWN"}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">Protocols</span>
                  <span className="font-semibold text-ink">
                    {protocol_summary.protocols_detected?.join(", ") || "UNKNOWN"}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">NAT-T Traversal</span>
                  <span className="font-semibold text-ink">
                    {protocol_summary.nat_detected ? "DETECTED" : "NOT OBSERVED"}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1">
                  <span className="text-ink-3">Observations</span>
                  <span className="font-semibold text-ink">
                    {protocol_summary.total_observations}
                  </span>
                </div>
              </div>
              <div className="pt-2">
                <Link
                  href={`/analyses/${analysisId}/protocol`}
                  className="inline-flex items-center gap-1 text-[13px] font-medium text-accent-ink hover:underline"
                >
                  <span>Details</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </Subsection>
          </div>

          <div className="border border-line bg-panel p-4">
            <Subsection title="Encrypted Traffic Inference">
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">Model Pipeline</span>
                  <span
                    className={`font-semibold ${
                      mlInferenceInactive ? "text-medium" : "text-positive"
                    }`}
                  >
                    {mlInferenceInactive
                      ? "NOT CONFIGURED (SKIPPED)"
                      : "ACTIVE"}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">Classified Flows</span>
                  <span className="font-semibold text-ink">
                    {traffic_summary.classified_flows}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">Classes Detected</span>
                  <span className="font-semibold text-ink">
                    {traffic_summary.classes_detected?.join(", ") || "None"}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1 border-b border-line">
                  <span className="text-ink-3">OOD / Unknown</span>
                  <span className="font-semibold text-medium">
                    {traffic_summary.ood_count}
                  </span>
                </div>
                <div className="flex justify-between gap-3 py-1">
                  <span className="text-ink-3">Behavioral Anomalies</span>
                  <span className="font-semibold text-high">
                    {traffic_summary.anomaly_count}
                  </span>
                </div>
              </div>
              <p className="pt-2 text-[11px] text-ink-3 font-mono leading-relaxed">
                {mlInferenceInactive
                  ? "No machine learning classifier bundle is deployed on this node. Inferences were safely skipped rather than producing synthetic claims."
                  : "Application classes inferred from encrypted packet timing and size metadata. Payload is not decrypted."}
              </p>
              <div className="pt-1">
                <Link
                  href={`/analyses/${analysisId}/traffic`}
                  className="inline-flex items-center gap-1 text-[13px] font-medium text-accent-ink hover:underline"
                >
                  <span>Flows</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </Subsection>
          </div>

          <div className="border border-line bg-panel p-4">
            <Subsection title="Metadata Fingerprintability">
              <div className="space-y-2">
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-mono font-bold text-ink">
                    {fingerprintability.overall_index}
                  </span>
                  <span className="text-xs font-mono text-ink-3">/ 100</span>
                  {fingerprintability.is_experimental && (
                    <span className="px-1.5 py-0.5 text-[11px] font-mono font-semibold uppercase bg-medium-bg text-medium border border-medium-border">
                      Experimental
                    </span>
                  )}
                </div>
                <p className="text-xs text-ink-3 font-mono leading-relaxed">
                  {fingerprintability.disclaimer ||
                    "Behavioral side-channel distinguishability of encrypted traffic under tested methodology."}
                </p>
              </div>
            </Subsection>
          </div>
        </div>
      </Section>
    </div>
  );
}
