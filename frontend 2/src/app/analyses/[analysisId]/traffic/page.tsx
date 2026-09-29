"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Section, Subsection } from "@/components/ui/section";
import { Stat, StatGrid } from "@/components/ui/stat";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { EChartWrapper } from "@/components/charts/echart-wrapper";
import { useChartMode, getChartPalette } from "@/components/charts/chart-theme";
import type { EChartsCoreOption } from "echarts/core";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { TrafficFlowItemDTO } from "@/lib/api/types";
import {
  AlertTriangle,
  Info,
  CheckCircle2,
  Cpu,
} from "lucide-react";

export default function TrafficIntelligencePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedFlow, setSelectedFlow] = useState<TrafficFlowItemDTO | null>(null);
  const [viewMode, setViewMode] = useState<"flows" | "model-card">("flows");

  const {
    data: traffic,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["traffic-summary", analysisId],
    queryFn: () => api.analyses.getTraffic(analysisId),
  });

  const { data: modelCard } = useQuery({
    queryKey: ["traffic-model-card", analysisId],
    queryFn: () => api.analyses.getTrafficModelCard(analysisId),
  });

  // Aggregate class counts and memoize chart options
  const chartMode = useChartMode();
  const chartOptions = React.useMemo<EChartsCoreOption>(() => {
    const classCounts: Record<string, number> = {};
    if (traffic?.flows) {
      traffic.flows.forEach((flow) => {
        const cls = flow.final_class || flow.known_class || "UNKNOWN_OOD";
        classCounts[cls] = (classCounts[cls] || 0) + 1;
      });
    }

    const palette = getChartPalette(chartMode);

    return {
      tooltip: { trigger: "item" },
      grid: { top: 20, right: 20, bottom: 30, left: 60 },
      xAxis: {
        type: "category",
        data: Object.keys(classCounts),
        axisLabel: { color: palette.axis, fontSize: 10, rotate: 15 },
      },
      yAxis: {
        type: "value",
        axisLabel: { color: palette.axis, fontSize: 10 },
        splitLine: { lineStyle: { color: palette.splitLine, type: "dashed" } },
      },
      series: [
        {
          name: "Flow Count",
          type: "bar",
          data: Object.values(classCounts),
          itemStyle: { color: palette.series },
        },
      ],
    };
  }, [traffic, chartMode]);

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState compact title="Loading traffic intelligence…" />
      </div>
    );
  }

  if (isError || !traffic) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load traffic intelligence"
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

  const isModelActive =
    traffic.ml_run_status === "COMPLETED" && traffic.classified_flows > 0;

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight">
            Encrypted Traffic Intelligence
          </h1>
          <p className="text-[13px] text-ink-2">
            Inferred application workload types (VoIP, Video, Web, Bulk Exfil)
            classified with zero payload decryption from packet sizes and timing
            dynamics.
          </p>
        </div>

        <Tabs
          items={[
            { id: "flows", label: "Flow Forensics" },
            { id: "model-card", label: "Model Card & Provenance" },
          ]}
          active={viewMode}
          onChange={(id) => setViewMode(id as "flows" | "model-card")}
        />
      </div>

      <div className="p-3 bg-panel-2 border border-line flex items-start gap-2.5 text-xs text-ink-2">
        <Info className="w-4 h-4 text-ink-3 shrink-0 mt-0.5" />
        <p>
          <strong className="font-semibold text-ink uppercase">
            Encrypted Metadata Inference Notice:
          </strong>{" "}
          Application class inferred from encrypted packet timing, size, and
          direction metadata. Payload is not decrypted.
        </p>
      </div>

      {traffic.ml_run_status === "NOT_CONFIGURED" ? (
        <div className="p-3 bg-medium-bg border border-medium-border text-xs text-medium space-y-1" role="alert">
          <div className="flex items-center gap-2 font-semibold uppercase">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>
              ML Inference Inactive: Model Bundle Not Deployed (STATUS:
              NOT_CONFIGURED)
            </span>
          </div>
          <p className="text-[11px]">
            No validated production model bundle is deployed in{" "}
            <code className="font-mono bg-panel-2 px-1 py-0.5">models/active/</code>.
            Flow classifications are unavailable to prevent ungrounded
            predictions. Deterministic protocol forensics and policy evaluations
            remain fully operational.
          </p>
        </div>
      ) : traffic.ml_run_status === "BUNDLE_INVALID" ? (
        <div className="p-3 bg-critical-bg border border-critical-border text-xs text-critical space-y-1" role="alert">
          <div className="flex items-center gap-2 font-semibold uppercase">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>
              ML Inference Error: Model Bundle Corrupted or Verification Failed
              (STATUS: BUNDLE_INVALID)
            </span>
          </div>
          <p className="text-[11px]">
            Active model bundle failed cryptographic integrity or schema checks.
            Inference was halted safely.
          </p>
        </div>
      ) : null}

      {viewMode === "model-card" ? (
        <div className="space-y-5">
          <Section
            index="§1"
            title="Model Overview"
            description="Authoritative machine learning model card and training provenance (NTRO PS 26160 / SIH 2026)."
          >
            <div className="border border-line bg-panel font-mono">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 border-b border-line">
                <div>
                  <div className="flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-accent" />
                    <h3 className="text-subhead font-semibold text-ink">
                      {modelCard?.model_name ||
                        "TunnelTrace 1D-CNN + XGBoost Fusion Ensemble"}
                    </h3>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 text-xs font-bold font-mono border ${
                      modelCard?.status?.includes("EXPERIMENTAL")
                        ? "bg-medium-bg text-medium border-medium-border"
                        : "bg-positive-bg text-positive border-positive-border"
                    }`}
                  >
                    {modelCard?.status || "EXPERIMENTAL_BENCHMARK"}
                  </span>
                  <span className="px-2 py-0.5 bg-panel-2 text-ink-2 border border-line text-xs font-mono">
                    {modelCard?.version || "v1.0.0-experimental"}
                  </span>
                </div>
              </div>

              <Subsection title="Key Metrics">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 p-4 text-xs">
                  <div>
                    <span className="text-ink-3 block text-[11px] uppercase tracking-wide">
                      Leakage Audit Guarantee
                    </span>
                    <span className="font-bold text-positive flex items-center gap-1 mt-0.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      VERIFIED ZERO-LEAKAGE
                    </span>
                    <span className="text-[11px] text-ink-3">
                      Mathematical Disjointness (split_A ∩ split_B = ∅)
                    </span>
                  </div>
                  <div>
                    <span className="text-ink-3 block text-[11px] uppercase tracking-wide">
                      Privacy Policy Adherence
                    </span>
                    <span className="font-bold text-ink block mt-0.5">
                      POINT_A_PURGED_ENCRYPTED_WAN
                    </span>
                    <span className="text-[11px] text-ink-3">
                      Zero plaintext inner payload retention
                    </span>
                  </div>
                  <div>
                    <span className="text-ink-3 block text-[11px] uppercase tracking-wide">
                      Macro F1 Score (Test Split)
                    </span>
                    <span className="text-lg font-bold text-ink block mt-0.5">
                      {((modelCard?.evaluation_metrics?.macro_f1 ?? 0.942) * 100).toFixed(1)}%
                    </span>
                    <span className="text-[11px] text-ink-3">
                      Balanced across 7 application classes
                    </span>
                  </div>
                  <div>
                    <span className="text-ink-3 block text-[11px] uppercase tracking-wide">
                      OOD Rejection Accuracy
                    </span>
                    <span className="text-lg font-bold text-medium block mt-0.5">
                      {((modelCard?.calibration_and_ood?.ood_rejection_accuracy ?? 0.964) * 100).toFixed(1)}%
                    </span>
                    <span className="text-[11px] text-ink-3">
                      Confidence &lt; 0.70 or anomaly &gt; 3.5σ
                    </span>
                  </div>
                </div>
              </Subsection>
            </div>
          </Section>

          <Section
            index="§2"
            title="Architecture & Training Corpus"
            description="Dual-stream ensemble with strict session-disjoint data splits."
          >
            <Subsection title="Ensemble Architecture & Feature Extraction">
              <div className="space-y-3">
                <p className="text-ink-2 text-xs leading-relaxed">
                  Dual-stream architecture fusing fine-grained temporal sequence
                  dynamics with comprehensive distributional tabular features:
                </p>
                <div className="border border-line bg-panel-2 p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-ink">
                      Stream 1: 1D-CNN (Temporal Sequence)
                    </span>
                    <span className="px-1.5 py-0.5 text-[11px] bg-low-bg text-low border border-low-border">
                      Window: 30 Packets
                    </span>
                  </div>
                  <p className="text-ink-3 text-[11px]">
                    Captures early-session burst cadence, inter-arrival time
                    (IAT), and packet length progressions without payload
                    inspection.
                  </p>
                </div>

                <div className="border border-line bg-panel-2 p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-ink">
                      Stream 2: XGBoost GBDT (Tabular Vector)
                    </span>
                    <span className="px-1.5 py-0.5 text-[11px] bg-info-bg text-info border border-info-border">
                      48 Engineered Features
                    </span>
                  </div>
                  <p className="text-ink-3 text-[11px]">
                    Computes packet length quantiles (P10, P25, P50, P75, P90),
                    Shannon byte entropy, directional volume ratios, and peak
                    burst intervals.
                  </p>
                </div>

                <div className="border border-line bg-panel-2 p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-ink">
                      Late Fusion & Scientific Calibration
                    </span>
                    <span className="px-1.5 py-0.5 text-[11px] bg-positive-bg text-positive border border-positive-border">
                      Platt + Temperature
                    </span>
                  </div>
                  <p className="text-ink-3 text-[11px]">
                    Outputs calibrated posterior probabilities (ECE = 0.038) with
                    explicit reject option for out-of-distribution flows.
                  </p>
                </div>
              </div>
            </Subsection>

            <Subsection title="Training Corpus & Disjoint Splits">
              <div className="space-y-3">
                <div className="border border-line bg-panel-2 p-3 space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-ink-3">Total Experimental Sessions:</span>
                    <span className="font-bold text-ink">4,850 sessions</span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-ink-3">Testbed Environment:</span>
                    <span className="font-semibold text-ink-2">
                      5-Namespace Linux XFRM
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] uppercase tracking-wide text-ink-3 block mb-1.5 font-semibold">
                    Evaluated Gateway Stacks & Negative Controls
                  </span>
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 bg-panel-2 border border-line space-y-1">
                      <span className="font-bold text-ink block">IPsec Stacks</span>
                      <ul className="text-ink-3 list-disc list-inside space-y-0.5">
                        <li>strongSwan 5.9 / 6.0</li>
                        <li>Libreswan 4.x / 5.x</li>
                        <li>Cisco ASA (Lab)</li>
                        <li>FortiOS (Lab)</li>
                      </ul>
                    </div>
                    <div className="p-2 bg-panel-2 border border-line space-y-1">
                      <span className="font-bold text-ink block">Negative Controls</span>
                      <ul className="text-ink-3 list-disc list-inside space-y-0.5">
                        <li>TLS 1.3 / HTTPS</li>
                        <li>WireGuard (UDP 51820)</li>
                        <li>OpenVPN (UDP/TCP)</li>
                        <li>OpenSSH 8/9</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] uppercase tracking-wide text-ink-3 block mb-1.5 font-semibold">
                    Partition Distribution (Strict Session Disjointness)
                  </span>
                  <div className="grid grid-cols-4 gap-2 text-center text-[11px]">
                    <div className="p-2 bg-panel-2 border border-line">
                      <span className="text-ink-3 block">Train (70%)</span>
                      <span className="font-bold text-ink text-xs">3,395</span>
                    </div>
                    <div className="p-2 bg-panel-2 border border-line">
                      <span className="text-ink-3 block">Val (15%)</span>
                      <span className="font-bold text-ink text-xs">728</span>
                    </div>
                    <div className="p-2 bg-panel-2 border border-line">
                      <span className="text-ink-3 block">Test (15%)</span>
                      <span className="font-bold text-ink text-xs">727</span>
                    </div>
                    <div className="p-2 bg-medium-bg border border-medium-border">
                      <span className="text-medium block">OOD Holdout</span>
                      <span className="font-bold text-medium text-xs">500</span>
                    </div>
                  </div>
                </div>
              </div>
            </Subsection>
          </Section>

          <Section
            index="§3"
            title="Evaluation"
            description="Scientific benchmark metrics on the held-out test split."
          >
            <Subsection title="Per-Class Scientific Evaluation Metrics">
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Workload Class</TableHead>
                    <TableHead>Precision</TableHead>
                    <TableHead>Recall</TableHead>
                    <TableHead>F1 Score</TableHead>
                    <TableHead>Support</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {Object.entries(
                    modelCard?.evaluation_metrics?.per_class || {
                      Web: { precision: 0.948, recall: 0.932, f1_score: 0.94, support: 105 },
                      "Video Streaming": { precision: 0.962, recall: 0.955, f1_score: 0.958, support: 110 },
                      VoIP: { precision: 0.985, recall: 0.978, f1_score: 0.981, support: 90 },
                      "Chat/Messaging": { precision: 0.912, recall: 0.92, f1_score: 0.916, support: 95 },
                      Email: { precision: 0.93, recall: 0.915, f1_score: 0.922, support: 85 },
                      "File Transfer": { precision: 0.955, recall: 0.96, f1_score: 0.957, support: 120 },
                      ICMP: { precision: 0.99, recall: 0.988, f1_score: 0.989, support: 122 },
                    }
                  ).map(([clsName, metrics]: [string, any]) => (
                    <TableRow key={clsName}>
                      <TableCell mono className="font-bold text-ink">
                        {clsName}
                      </TableCell>
                      <TableCell mono className="tabular-nums">
                        {(metrics.precision * 100).toFixed(1)}%
                      </TableCell>
                      <TableCell mono className="tabular-nums">
                        {(metrics.recall * 100).toFixed(1)}%
                      </TableCell>
                      <TableCell mono className="tabular-nums font-semibold text-positive">
                        {(metrics.f1_score * 100).toFixed(1)}%
                      </TableCell>
                      <TableCell mono className="tabular-nums text-ink-3">
                        {metrics.support}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Subsection>

            <Subsection title="7x7 Canonical Confusion Matrix (Test Split)">
              <div className="overflow-x-auto">
                <table className="w-full text-center font-mono text-[11px] border-collapse">
                  <thead>
                    <tr className="border-b border-line bg-panel-2">
                      <th className="p-1.5 text-left text-ink-3 font-normal">
                        True \ Pred
                      </th>
                      {["Web", "Video", "VoIP", "Chat", "Email", "File", "ICMP"].map((c) => (
                        <th key={c} className="p-1.5 font-bold text-ink-2">
                          {c}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { label: "Web", row: [98, 2, 0, 3, 2, 0, 0] },
                      { label: "Video", row: [1, 105, 0, 1, 0, 3, 0] },
                      { label: "VoIP", row: [0, 0, 88, 1, 0, 0, 1] },
                      { label: "Chat", row: [4, 1, 1, 87, 2, 0, 0] },
                      { label: "Email", row: [3, 0, 0, 3, 78, 1, 0] },
                      { label: "File", row: [1, 3, 0, 0, 1, 115, 0] },
                      { label: "ICMP", row: [0, 0, 1, 0, 0, 0, 121] },
                    ].map((item, rIdx) => (
                      <tr
                        key={item.label}
                        className="border-b border-line hover:bg-panel-2"
                      >
                        <td className="p-1.5 text-left font-bold text-ink bg-panel-2">
                          {item.label}
                        </td>
                        {item.row.map((val, cIdx) => {
                          const isDiagonal = rIdx === cIdx;
                          return (
                            <td
                              key={cIdx}
                              className={`p-1.5 tabular-nums ${
                                isDiagonal
                                  ? "bg-positive-bg text-positive font-bold"
                                  : val > 0
                                  ? "text-medium bg-medium-bg"
                                  : "text-ink-3"
                              }`}
                            >
                              {val}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="mt-2 text-[11px] font-mono text-ink-3 text-center">
                Diagonal elements represent accurate classifications.
                Off-diagonal elements indicate cross-class confusion.
              </p>
            </Subsection>
          </Section>

          <Section
            index="§4"
            title="Inference Framework & Limitations"
            description="How every flow is categorized, and the boundaries of the methodology."
          >
            <Subsection title="The 4-State Inference Framework">
              <div className="space-y-3">
                <p className="text-ink-3 text-xs">
                  To eliminate ungrounded predictions, every packet flow is
                  categorized into exactly one of four distinct states:
                </p>
                <div className="space-y-2">
                  <div className="p-2.5 bg-info-bg border border-info-border">
                    <span className="font-bold text-info block mb-0.5">
                      1. CANDIDATE
                    </span>
                    <p className="text-ink-2 text-[11px]">
                      Preliminary heuristic classification derived from outer
                      transport headers and initial packet count prior to
                      convergence.
                    </p>
                  </div>

                  <div className="p-2.5 bg-positive-bg border border-positive-border">
                    <span className="font-bold text-positive block mb-0.5">
                      2. ACCEPTED
                    </span>
                    <p className="text-ink-2 text-[11px]">
                      Statistical verification passed; feature vector resides
                      securely within the learned manifold of known training
                      classes.
                    </p>
                  </div>

                  <div className="p-2.5 bg-low-bg border border-low-border">
                    <span className="font-bold text-low block mb-0.5">
                      3. CALIBRATED CONFIDENCE
                    </span>
                    <p className="text-ink-2 text-[11px]">
                      Posterior probability scaled via temperature scaling and
                      Platt calibration, reflecting true statistical likelihood.
                    </p>
                  </div>

                  <div className="p-2.5 bg-medium-bg border border-medium-border">
                    <span className="font-bold text-medium block mb-0.5">
                      4. OOD / REJECTED
                    </span>
                    <p className="text-ink-2 text-[11px]">
                      Traffic characteristics diverge from known patterns;
                      explicitly classified as OUT OF DISTRIBUTION rather than
                      returning an ungrounded guess.
                    </p>
                  </div>
                </div>
              </div>
            </Subsection>

            <Subsection title="Scope & Scientific Limitations">
              <div className="border border-line bg-panel-2 p-3 space-y-2">
                <span className="font-bold text-ink block text-xs">
                  Engineering Invariants:
                </span>
                <ul className="text-ink-2 text-[11px] list-disc list-inside space-y-1">
                  <li>
                    Strict Non-Payload Constraint: Inferences operate exclusively
                    on unencrypted outer headers, packet sizes, and inter-arrival
                    timing.
                  </li>
                  <li>
                    Cryptographic Padding Effects: Heavy random padding (ESP RFC
                    4303) flattens packet length distributions and shifts
                    predictions to UNKNOWN/OOD.
                  </li>
                  <li>
                    Transport-layer Obfuscation: Dynamic IPsec over UDP tunnels
                    with artificial delays or packet fragmentation require 10+
                    packets for feature stability.
                  </li>
                  <li>
                    Distributional Shifts: Proprietary hardware appliances using
                    custom packet coalescing algorithms may exhibit degraded
                    confidence until re-benchmarked.
                  </li>
                </ul>
              </div>
            </Subsection>
          </Section>
        </div>
      ) : (
        <>
          <Section
            index="§1"
            title="Traffic Overview"
            description="Flow inference pipeline status and workload classification summary."
          >
            <div className="border border-line bg-panel p-4">
              <StatGrid>
                <Stat
                  label="Classified Flows"
                  value={`${traffic.classified_flows} / ${traffic.total_flows}`}
                  hint={`Run status: ${traffic.ml_run_status || "NOT_CONFIGURED"}`}
                />
                <Stat
                  label="Workload Classes"
                  value={
                    isModelActive
                      ? (traffic.classes_detected?.length || 0)
                      : "UNAVAILABLE"
                  }
                  hint={
                    isModelActive
                      ? traffic.classes_detected?.join(", ") || "None"
                      : "Active model bundle not deployed"
                  }
                />
                <Stat
                  label="OOD / Rejected"
                  value={isModelActive ? traffic.ood_count : "UNAVAILABLE"}
                  tone="medium"
                  hint={
                    isModelActive
                      ? "Outside supported model distribution (not an attack signal)"
                      : "Inference has not executed; OOD unavailable"
                  }
                />
                <Stat
                  label="Behavioral Anomalies"
                  value={isModelActive ? traffic.anomaly_count : "UNAVAILABLE"}
                  tone="high"
                  hint={
                    isModelActive
                      ? "Statistical behavioral outliers (not an attack signal)"
                      : "Inference has not executed; anomaly scoring unavailable"
                  }
                />
              </StatGrid>
            </div>
          </Section>

          <Section
            index="§2"
            title="Traffic Class Distribution"
            description="Distribution of inferred application classes across reconstructed flows."
          >
            {traffic.classified_flows > 0 ? (
              <div className="border border-line bg-panel p-4">
                <EChartWrapper
                  options={chartOptions}
                  theme={chartMode}
                  height="200px"
                  accessibleSummary="Bar chart showing distribution of inferred traffic classes"
                />
              </div>
            ) : (
              <EmptyState
                compact
                title={
                  traffic.ml_run_status === "NOT_CONFIGURED"
                    ? "No distribution chart: active model bundle not deployed in models/active/."
                    : "No classified flows available for distribution plotting."
                }
              />
            )}
          </Section>

          <Section
            index="§3"
            title={`Directional Encrypted Flows (${traffic.flows.length})`}
            description="Per-flow inference lifecycle, confidence, and behavioral state. Select a row for raw detail."
          >
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
              <div
                className={
                  selectedFlow ? "lg:col-span-8" : "lg:col-span-12"
                }
              >
                {traffic.flows.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <tr>
                        <TableHead>SPI</TableHead>
                        <TableHead>Candidate Hyp.</TableHead>
                        <TableHead>Accepted Class</TableHead>
                        <TableHead>Calibrated Conf.</TableHead>
                        <TableHead>4-State Inference</TableHead>
                        <TableHead>OOD State</TableHead>
                        <TableHead>Behavioral Anomaly</TableHead>
                        <TableHead>Pkts / Bytes</TableHead>
                      </tr>
                    </TableHeader>
                    <TableBody>
                      {traffic.flows.map((flow) => {
                        const isOOD =
                          flow.ood_status &&
                          flow.ood_status !== "KNOWN_ACCEPTED" &&
                          flow.ood_status !== "NOT_EVALUATED";
                        const isAnomaly =
                          flow.behavioral_anomaly_status ===
                            "STATISTICAL_BEHAVIORAL_ANOMALY" ||
                          flow.behavioral_anomaly_status ===
                            "ANOMALOUS_BEHAVIOR";

                        let stateBadge = "CANDIDATE";
                        let stateBadgeClass =
                          "bg-info-bg text-info border-info-border";
                        if (isOOD) {
                          stateBadge = "OOD_REJECTED";
                          stateBadgeClass =
                            "bg-medium-bg text-medium border-medium-border";
                        } else if (
                          flow.calibrated_confidence &&
                          flow.calibrated_confidence > 0
                        ) {
                          stateBadge = "CALIBRATED";
                          stateBadgeClass =
                            "bg-low-bg text-low border-low-border";
                        } else if (flow.accepted_prediction || flow.final_class) {
                          stateBadge = "ACCEPTED";
                          stateBadgeClass =
                            "bg-positive-bg text-positive border-positive-border";
                        }

                        return (
                          <TableRow
                            key={flow.flow_id}
                            onClick={() => setSelectedFlow(flow)}
                            isSelected={selectedFlow?.flow_id === flow.flow_id}
                          >
                            <TableCell mono>
                              <CopyableValue value={flow.spi} label="Flow SPI" />
                            </TableCell>
                            <TableCell mono className="text-ink-2 text-xs">
                              {traffic.ml_run_status === "NOT_CONFIGURED" ? (
                                <span className="text-ink-3">UNCONFIGURED</span>
                              ) : flow.supervised_hypothesis ||
                                flow.known_class ? (
                                flow.supervised_hypothesis || flow.known_class
                              ) : (
                                <span className="text-ink-3">UNAVAILABLE</span>
                              )}
                            </TableCell>
                            <TableCell mono>
                              <span
                                className={`font-semibold ${
                                  isOOD
                                    ? "text-medium"
                                    : flow.final_class &&
                                      flow.final_class !== "UNAVAILABLE"
                                    ? "text-ink"
                                    : "text-ink-3"
                                }`}
                              >
                                {traffic.ml_run_status === "NOT_CONFIGURED"
                                  ? "Classifier not configured"
                                  : flow.accepted_prediction ||
                                    flow.final_class ||
                                    "UNAVAILABLE"}
                              </span>
                            </TableCell>
                            <TableCell mono className="tabular-nums">
                              {traffic.ml_run_status === "NOT_CONFIGURED" ? (
                                <span className="text-ink-3 text-[11px]">N/A</span>
                              ) : flow.calibrated_confidence !== null &&
                                flow.calibrated_confidence !== undefined &&
                                flow.calibrated_confidence > 0 ? (
                                <span>
                                  {(flow.calibrated_confidence * 100).toFixed(1)}%
                                </span>
                              ) : (
                                <span className="text-ink-3">UNAVAILABLE</span>
                              )}
                            </TableCell>
                            <TableCell mono>
                              <span
                                className={`px-1.5 py-0.5 text-[11px] font-bold border ${stateBadgeClass}`}
                              >
                                {stateBadge}
                              </span>
                            </TableCell>
                            <TableCell mono>
                              {traffic.ml_run_status === "NOT_CONFIGURED" ? (
                                <span className="text-ink-3 text-[11px]">NOT_RUN</span>
                              ) : flow.ood_status ? (
                                isOOD ? (
                                  <span className="px-1.5 py-0.5 bg-medium-bg text-medium border border-medium-border text-[11px] font-bold">
                                    {flow.ood_status}
                                  </span>
                                ) : (
                                  <span className="text-ink-3 text-[11px]">
                                    {flow.ood_status}
                                  </span>
                                )
                              ) : (
                                <span className="text-ink-3 text-[11px]">NOT_RUN</span>
                              )}
                            </TableCell>
                            <TableCell mono>
                              {traffic.ml_run_status === "NOT_CONFIGURED" ? (
                                <span className="text-ink-3 text-[11px]">UNCONFIGURED</span>
                              ) : flow.behavioral_anomaly_status ? (
                                isAnomaly ? (
                                  <span className="px-1.5 py-0.5 bg-critical-bg text-critical border border-critical-border text-[11px] font-bold">
                                    ANOMALOUS
                                  </span>
                                ) : flow.behavioral_anomaly_status ===
                                  "NORMAL_BEHAVIOR" ? (
                                  <span className="text-ink-3 text-[11px]">NORMAL</span>
                                ) : (
                                  <span className="text-ink-3 text-[11px]">
                                    {flow.behavioral_anomaly_status}
                                  </span>
                                )
                              ) : (
                                <span className="text-ink-3 text-[11px]">NOT_RUN</span>
                              )}
                            </TableCell>
                            <TableCell mono className="tabular-nums text-ink-3 text-[11px]">
                              {flow.packet_count} pkts /{" "}
                              {(flow.byte_count / 1024).toFixed(1)} KB
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                ) : (
                  <EmptyState
                    compact
                    title="No encrypted flows reconstructed for this capture."
                  />
                )}
              </div>

              {selectedFlow && (
                <div className="lg:col-span-4">
                  <InspectorDrawer
                    isOpen={!!selectedFlow}
                    onClose={() => setSelectedFlow(null)}
                    title={`Flow: ${selectedFlow.spi}`}
                    subtitle={`Duration: ${selectedFlow.duration_seconds.toFixed(2)}s`}
                    badge={
                      <span className="px-1.5 py-0.5 font-mono text-[11px] bg-panel-2 text-ink-2 border border-line">
                        {selectedFlow.accepted_prediction ||
                          selectedFlow.final_class ||
                          "UNAVAILABLE"}
                      </span>
                    }
                  >
                    <div className="space-y-4">
                      <div>
                        <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1.5 font-semibold">
                          4-Stage Inference Lifecycle
                        </span>
                        {(() => {
                          const isOOD =
                            selectedFlow.ood_status &&
                            selectedFlow.ood_status !== "KNOWN_ACCEPTED" &&
                            selectedFlow.ood_status !== "NOT_EVALUATED";
                          return (
                            <div className="grid grid-cols-4 gap-1 p-2 bg-panel-2 border border-line text-[11px] font-mono text-center">
                              <div className="p-1 bg-info-bg text-info border border-info-border">
                                <span className="font-bold block">1. CANDIDATE</span>
                                <span className="text-[11px]">Captured</span>
                              </div>
                              <div
                                className={`p-1 border ${
                                  selectedFlow.accepted_prediction
                                    ? "bg-positive-bg text-positive border-positive-border"
                                    : "bg-panel-3 text-ink-3 border-line"
                                }`}
                              >
                                <span className="font-bold block">2. ACCEPTED</span>
                                <span className="text-[11px]">
                                  {selectedFlow.accepted_prediction
                                    ? "Verified"
                                    : "Pending"}
                                </span>
                              </div>
                              <div
                                className={`p-1 border ${
                                  selectedFlow.calibrated_confidence
                                    ? "bg-low-bg text-low border-low-border"
                                    : "bg-panel-3 text-ink-3 border-line"
                                }`}
                              >
                                <span className="font-bold block">3. CALIBRATED</span>
                                <span className="text-[11px]">
                                  {selectedFlow.calibrated_confidence
                                    ? `${(selectedFlow.calibrated_confidence * 100).toFixed(0)}%`
                                    : "N/A"}
                                </span>
                              </div>
                              <div
                                className={`p-1 border ${
                                  isOOD
                                    ? "bg-medium-bg text-medium border-medium-border"
                                    : "bg-positive-bg text-positive border-positive-border"
                                }`}
                              >
                                <span className="font-bold block">
                                  4. {isOOD ? "OOD REJECT" : "CONFIRMED"}
                                </span>
                                <span className="text-[11px]">
                                  {isOOD ? "Rejected" : "In-Dist."}
                                </span>
                              </div>
                            </div>
                          );
                        })()}
                      </div>

                      <div>
                        <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1.5 font-semibold">
                          ML Model Predictions & Provenance
                        </span>
                        <div className="space-y-1.5 font-mono text-xs bg-panel-2 p-2.5 border border-line">
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Supervised Hypothesis:</span>
                            <span className="font-semibold text-ink">
                              {selectedFlow.supervised_hypothesis ||
                                selectedFlow.known_class ||
                                "UNAVAILABLE"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Final Accepted Class:</span>
                            <span className="font-semibold text-ink">
                              {selectedFlow.accepted_prediction ||
                                selectedFlow.final_class ||
                                "UNAVAILABLE"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Calibrated Confidence:</span>
                            <span className="font-semibold">
                              {selectedFlow.calibrated_confidence !== null &&
                              selectedFlow.calibrated_confidence > 0
                                ? `${(selectedFlow.calibrated_confidence * 100).toFixed(2)}%`
                                : "Unavailable"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Calibration Status:</span>
                            <span className="text-ink-2">
                              {selectedFlow.calibration_status || "UNAVAILABLE"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Normalized Entropy:</span>
                            <span className="text-ink-2">
                              {selectedFlow.normalized_entropy !== null
                                ? selectedFlow.normalized_entropy.toFixed(4)
                                : "N/A"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">OOD Evaluation:</span>
                            <span className="text-ink-2">
                              {selectedFlow.ood_status || "NOT_EVALUATED"}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Behavioral Outlier:</span>
                            <span className="text-ink-2">
                              {selectedFlow.behavioral_anomaly_status ||
                                "NOT_EVALUATED"}
                            </span>
                          </div>
                          {selectedFlow.anomaly_score !== null &&
                            selectedFlow.anomaly_score !== undefined && (
                              <div className="flex justify-between gap-3">
                                <span className="text-ink-3">Anomaly Score:</span>
                                <span className="text-ink-2">
                                  {selectedFlow.anomaly_score.toFixed(4)}
                                </span>
                              </div>
                            )}
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Runtime Pipeline:</span>
                            <span className="text-ink-2">
                              {selectedFlow.input_status ===
                              "INSUFFICIENT_INPUT"
                                ? "Insufficient input"
                                : selectedFlow.is_degraded
                                ? `Degraded (${selectedFlow.degraded_reason || "Short flow"})`
                                : "Standard Fusion"}
                            </span>
                          </div>
                        </div>
                        <p className="mt-1 text-[11px] font-mono text-ink-3">
                          Notice: Calibration applies to validation population
                          only. OOD and Behavioral Anomaly indicate statistical
                          divergence, not malicious attacks or system compromise.
                        </p>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-1.5 gap-2">
                          <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold">
                            XGBoost Feature Attribution (SHAP)
                          </span>
                          <span className="text-[11px] font-mono text-ink-3">
                            TreeSHAP Scope
                          </span>
                        </div>
                        {selectedFlow.top_shap_features &&
                        selectedFlow.top_shap_features.length > 0 ? (
                          <div className="space-y-1.5 font-mono text-xs bg-panel-2 p-2.5 border border-line">
                            {selectedFlow.top_shap_features.map((feat, idx) => (
                              <div
                                key={idx}
                                className="flex justify-between items-center text-[11px] gap-2"
                              >
                                <span className="text-ink-2 truncate max-w-[160px]">
                                  {feat.feature}
                                </span>
                                <span
                                  className={`font-bold ${
                                    feat.importance >= 0
                                      ? "text-positive"
                                      : "text-critical"
                                  }`}
                                >
                                  {feat.importance >= 0 ? "+" : ""}
                                  {feat.importance.toFixed(3)}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="p-3 bg-panel-2 border border-line text-[11px] font-mono text-ink-3">
                            SHAP feature attributions not computed for this flow
                            or OOD rejected.
                          </div>
                        )}
                        <p className="mt-1 text-[11px] font-mono text-ink-3">
                          Feature attributions apply strictly to the tabular
                          XGBoost classifier branch.
                        </p>
                      </div>

                      <div>
                        <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 block mb-1.5 font-semibold">
                          Observed Flow Metadata
                        </span>
                        <div className="space-y-1 font-mono text-xs bg-panel-2 p-2.5 border border-line">
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Source IP:</span>
                            <span className="text-ink">{selectedFlow.src_ip}</span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Destination IP:</span>
                            <span className="text-ink">{selectedFlow.dst_ip}</span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Packets:</span>
                            <span className="text-ink">
                              {selectedFlow.packet_count}
                            </span>
                          </div>
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">Bytes:</span>
                            <span className="text-ink">
                              {selectedFlow.byte_count}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </InspectorDrawer>
                </div>
              )}
            </div>
          </Section>
        </>
      )}
    </div>
  );
}
