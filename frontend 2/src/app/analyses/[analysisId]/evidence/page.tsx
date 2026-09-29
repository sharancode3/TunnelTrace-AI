"use client";

import React, { use, useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "@/lib/api/client";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { Section } from "@/components/ui/section";
import { Tabs } from "@/components/ui/tabs";
import { EmptyState } from "@/components/ui/empty-state";
import { Button, ButtonLink } from "@/components/ui/button";
import { Stat, StatGrid } from "@/components/ui/stat";
import { CopyableValue } from "@/components/ui/table";
import { SocWorkflowBanner } from "@/components/soc/soc-workflow-banner";
import { easeOutExpo, prefersReducedMotion } from "@/lib/motion";
import {
  AlertTriangle,
  HelpCircle,
  ArrowRight,
  Layers,
  History,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ExternalLink,
  FileText,
  Shield,
  ChevronRight,
} from "lucide-react";

type EvidenceViewMode = "graph" | "table" | "lineage" | "replay";

function EvidenceExplorerContent({
  analysisId,
}: {
  analysisId: string;
}) {
  const searchParams = useSearchParams();
  const highlightedFindingId = searchParams.get("findingId");
  const viewParam = searchParams.get("view");

  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [viewMode, setViewMode] = useState<EvidenceViewMode>(
    viewParam === "replay" || viewParam === "lineage" || viewParam === "table" ? viewParam : "graph"
  );
  const [isReanalyzing, setIsReanalyzing] = useState(false);
  const [reanalysisResult, setReanalysisResult] = useState<any | null>(null);
  const [reanalysisError, setReanalysisError] = useState<string | null>(null);
  const [showProvenance, setShowProvenance] = useState(false);

  useEffect(() => {
    if (viewParam === "replay" || viewParam === "lineage" || viewParam === "graph" || viewParam === "table") {
      setViewMode(viewParam);
    }
  }, [viewParam]);

  const {
    data: evidence,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["evidence-graph", analysisId],
    queryFn: () => api.analyses.getEvidenceGraph(analysisId),
  });

  const {
    data: replayLineage,
    refetch: refetchReplay,
  } = useQuery({
    queryKey: ["replay-lineage", analysisId],
    queryFn: () => api.analyses.getReplayLineage(analysisId),
  });

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (evidence) {
      const rawNodes = evidence.nodes?.length ? evidence.nodes : (evidence as any).react_flow?.nodes || [];
      const rawEdges = evidence.edges?.length ? evidence.edges : (evidence as any).react_flow?.edges || [];

      if (rawNodes.length > 0) {
        // Semantic node-type palette — resolves through theme variables in light & dark
        const typeColors: Record<string, string> = {
          finding: "var(--color-critical)",
          security_finding: "var(--color-critical)",
          rule: "var(--color-medium)",
          policy_rule: "var(--color-medium)",
          fact: "var(--color-low)",
          security_fact: "var(--color-low)",
          observation: "var(--color-positive)",
          protocol_observation: "var(--color-positive)",
          compliance_evaluation: "var(--color-high)",
          evidence_gap: "var(--color-medium)",
          packet: "var(--color-accent)",
          frame: "var(--color-accent)",
          capture: "var(--color-ink-3)",
          threat: "var(--color-critical)",
          risk_result: "var(--color-critical)",
          fingerprintability_component: "var(--color-high)",
          esp_flow: "var(--color-low)",
          scenario: "var(--color-positive)",
          replay_run: "var(--color-ink-3)",
        };

        const getEvidenceTier = (nodeType: string): number => {
          const t = (nodeType || "").toLowerCase();
          if (t.includes("capture") || t.includes("scenario")) return 0;
          if (t.includes("packet") || t.includes("frame")) return 1;
          if (t.includes("observation") || t.includes("esp_flow")) return 2;
          if (t.includes("fact")) return 3;
          if (t.includes("rule")) return 4;
          if (t.includes("eval") || t.includes("gap")) return 5;
          if (t.includes("finding")) return 6;
          if (t.includes("threat") || t.includes("risk")) return 7;
          if (t.includes("score") || t.includes("fingerprint") || t.includes("remediation")) return 8;
          return 3;
        };

        const presentTiers: number[] = Array.from(
          new Set<number>(
            rawNodes.map((n: any) =>
              getEvidenceTier(n.node_type || n.type || n.data?.nodeType || "")
            )
          )
        ).sort((a: number, b: number) => a - b);
        const tierToColIndex = new Map(presentTiers.map((tier, idx) => [tier, idx]));

        const NODE_WIDTH = 230;
        const HORIZ_GAP = 240;
        const VERT_STEP = 160;

        const tierCounts: Record<number, number> = {};
        presentTiers.forEach((t: number) => {
          tierCounts[t] = 0;
        });

        const formattedNodes: Node[] = rawNodes.map((n: any) => {
          const nodeType = String(n.node_type || n.type || n.data?.nodeType || "NODE").toLowerCase();
          const rawLabel = n.label || n.data?.label || n.id;
          const entityId = n.entity_id || n.data?.finding_id || n.data?.rule_id || n.data?.fact_id || n.data?.subject_id || n.id;
          const tier = getEvidenceTier(nodeType);
          const yIndex = tierCounts[tier] || 0;
          tierCounts[tier] = yIndex + 1;

          const colIndex = tierToColIndex.get(tier) ?? 0;
          const xPos = 40 + colIndex * (NODE_WIDTH + HORIZ_GAP);
          const yPos = 40 + yIndex * VERT_STEP;

          const isHighlight =
            highlightedFindingId && (entityId === highlightedFindingId || n.id === highlightedFindingId);

          const borderColor =
            typeColors[nodeType] ||
            typeColors[nodeType.replace(/_/g, "")] ||
            "var(--color-ink-3)";

          return {
            id: n.id,
            type: "default",
            sourcePosition: Position.Right,
            targetPosition: Position.Left,
            data: {
              label: `${(n.node_type || n.type || n.data?.nodeType || "NODE").toUpperCase()}\n${rawLabel}`,
              nodeType: n.node_type || n.type || n.data?.nodeType || "NODE",
              labelRaw: rawLabel,
              entityId,
              properties: n.properties || n.data || {},
            },
            position: { x: xPos, y: yPos },
            style: {
              background: isHighlight ? "var(--color-accent)" : "var(--color-panel)",
              color: isHighlight ? "var(--color-on-accent)" : "var(--color-ink)",
              border: isHighlight
                ? "2px solid var(--color-accent)"
                : `1.5px solid ${borderColor}`,
              borderRadius: 0,
              fontFamily: "monospace",
              fontSize: "11px",
              padding: "10px 12px",
              width: NODE_WIDTH,
            },
          };
        });

        const validNodeIds = new Set(formattedNodes.map((n) => n.id));

        const formattedEdges: Edge[] = rawEdges
          .map((e: any, idx: number) => {
            const src = e.source || e.source_id || e.source_node_id || "";
            const tgt = e.target || e.target_id || e.target_node_id || "";
            const lbl = e.label || e.relation_type || e.relation || "";
            return {
              id: e.id || `e-${idx}-${src}-${tgt}`,
              source: src,
              target: tgt,
              label: lbl,
              type: "smoothstep",
              style: { stroke: "var(--color-ink-3)", strokeWidth: 1.5 },
              labelStyle: {
                fill: "var(--color-ink)",
                fontSize: 9,
                fontFamily: "ui-monospace, monospace",
                fontWeight: 600,
                letterSpacing: "0.03em",
              },
              labelBgStyle: {
                fill: "var(--color-panel)",
                fillOpacity: 0.95,
                stroke: "var(--color-line-strong)",
                strokeWidth: 1,
                rx: 0,
                ry: 0,
              },
              labelBgPadding: [6, 2] as [number, number],
            };
          })
          .filter((e: any) => e.source && e.target && validNodeIds.has(e.source) && validNodeIds.has(e.target));

        setNodes(formattedNodes);
        setEdges(formattedEdges);
      }
    }
  }, [evidence, highlightedFindingId, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    const rawNode =
      (evidence?.nodes || []).find((n) => n.id === node.id) ||
      (evidence as any)?.react_flow?.nodes?.find((n: any) => n.id === node.id) ||
      node;

    const nodeType = (rawNode as any).node_type || (rawNode as any).type || (rawNode as any).data?.nodeType || "NODE";
    const label = (rawNode as any).label || (rawNode as any).data?.labelRaw || (rawNode as any).data?.label || rawNode.id;
    const entityId = (rawNode as any).entity_id || (rawNode as any).data?.entityId || (rawNode as any).data?.subject_id || (rawNode as any).data?.rule_id || rawNode.id;
    const properties = (rawNode as any).properties || (rawNode as any).data?.properties || (rawNode as any).data || {};

    setSelectedNode({
      id: rawNode.id,
      node_type: nodeType,
      label,
      entity_id: entityId,
      properties,
    });
  };

  const computedGaps = React.useMemo(() => {
    if (evidence?.evidence_gaps && evidence.evidence_gaps.length > 0) {
      return evidence.evidence_gaps;
    }
    const rawNodes = evidence?.nodes?.length ? evidence.nodes : (evidence as any)?.react_flow?.nodes || [];
    return (rawNodes || [])
      .filter((n: any) => {
        const t = String(n.type || n.node_type || n.data?.nodeType || "").toLowerCase();
        return t.includes("gap");
      })
      .map((n: any) => ({
        fact_name: n.data?.rule_id || (Array.isArray(n.data?.missing_fields) ? n.data.missing_fields.join(", ") : null) || n.label || "Missing Protocol Evidence",
        rationale: n.data?.reason || n.data?.recommended_action || "Required protocol evidence missing or unobserved in passive capture.",
      }));
  }, [evidence]);

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState
          compact
          title="Assembling evidence DAG…"
          description="Tracing forensic packet provenance across this run."
        />
      </div>
    );
  }

  if (isError || !evidence) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load evidence graph"
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

  const nodeCount = (evidence?.nodes || []).length;
  const integrityVerified = Boolean(replayLineage?.capture_integrity_verified);
  const comparisonMatch =
    replayLineage?.latest_comparison?.comparison_status === "EXACT_MATCH" ||
    replayLineage?.latest_comparison?.comparison_status === "SEMANTIC_MATCH";

  const labelCls = "text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold";

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      {/* SOC Analyst Lifecycle Banner */}
      <SocWorkflowBanner
        activeStep={viewMode === "replay" ? 6 : 5}
        analysisId={analysisId}
      />

      <header className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-xl font-semibold text-ink tracking-tight">
              Forensic Evidence Explorer
            </h1>
            <p className="text-[13px] text-ink-2">
              The immutable evidence chain linking findings to policy rules,
              protocol facts, packet frame numbers, and capture SHA-256 digests —
              including gaps where data was absent.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <ButtonLink
              href={`/analyses/${analysisId}/security`}
              variant="secondary"
              size="sm"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Findings Triage</span>
            </ButtonLink>
            <ButtonLink
              href={`/analyses/${analysisId}/reports`}
              variant="primary"
              size="sm"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Generate Report</span>
            </ButtonLink>
          </div>
        </div>

        <Tabs
          items={[
            { id: "graph", label: "Interactive DAG", count: nodeCount },
            { id: "table", label: "Table View", count: nodeCount },
            { id: "lineage", label: "Textual Traversal", count: nodeCount },
            {
              id: "replay",
              label: "Replay Lineage",
              count: replayLineage?.child_runs?.length,
            },
          ]}
          active={viewMode}
          onChange={(id) => setViewMode(id as EvidenceViewMode)}
        />
      </header>

      {/* §1 Concise evidence summary */}
      <Section
        index="§1"
        title="Evidence Summary"
        description="Provenance facts for this run — node/link counts, gaps, and capture lineage."
      >
        <div className="border border-line bg-panel p-4 space-y-4">
          <StatGrid>
            <Stat
              label="Evidence Nodes"
              value={nodeCount}
              hint="graph entities reconstructed"
            />
            <Stat
              label="Provenance Links"
              value={(evidence?.edges || []).length}
              hint="typed source → target relations"
            />
            <Stat
              label="Evidence Gaps"
              value={computedGaps.length}
              tone={computedGaps.length > 0 ? "medium" : "default"}
              hint="required facts absent from capture"
            />
            <Stat
              label="Child Replay Runs"
              value={replayLineage?.child_runs?.length || 0}
              tone="info"
              hint={replayLineage?.replay_mode || "ORIGINAL_INGESTION"}
            />
          </StatGrid>

          <div className="pt-3 border-t border-line flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] font-mono text-ink-3">
            <span>
              Capture:{" "}
              <span className="text-ink-2 font-semibold">
                {replayLineage?.capture_filename || "unknown"}
              </span>
            </span>
            <span className="flex items-center gap-1.5">
              SHA-256:{" "}
              {replayLineage?.capture_sha256 ? (
                <CopyableValue
                  value={replayLineage.capture_sha256}
                  truncate
                  label="Capture SHA-256"
                />
              ) : (
                <span>unknown</span>
              )}
            </span>
            <span>
              Replay mode:{" "}
              <span className="text-ink-2 font-semibold">
                {replayLineage?.replay_mode || "ORIGINAL_INGESTION"}
              </span>
            </span>
            <span
              className={`px-1.5 py-0.5 border ${
                integrityVerified
                  ? "bg-positive-bg border-positive-border text-positive"
                  : "bg-critical-bg border-critical-border text-critical"
              }`}
            >
              {integrityVerified
                ? "ARTIFACT INTEGRITY VERIFIED"
                : "ARTIFACT INTEGRITY UNVERIFIED"}
            </span>
          </div>
        </div>
      </Section>

      {viewMode === "replay" ? (
        /* ---------- Replay diff view ---------- */
        <Section
          index="§2"
          title="Replay Diff & Reproducibility"
          description="Re-run the same verified capture artifact and compare results deterministically."
        >
          <div className="space-y-4">
            {/* Top status & integrity banner */}
            <div className="border border-line bg-panel p-4 space-y-3">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={labelCls}>Analysis lineage</span>
                    <span className="font-mono text-sm font-semibold text-ink">
                      {analysisId}
                    </span>
                    <span className="px-1.5 py-0.5 font-mono text-[11px] bg-panel-2 border border-line text-ink-2">
                      {replayLineage?.replay_mode || "ORIGINAL_INGESTION"}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-ink-3 flex flex-wrap items-center gap-3">
                    <span>Capture: {replayLineage?.capture_filename || "unknown"}</span>
                    <span>
                      SHA-256:{" "}
                      {replayLineage?.capture_sha256
                        ? `${replayLineage.capture_sha256.slice(0, 16)}...`
                        : "unknown"}
                    </span>
                  </div>
                </div>

                {/* Artifact integrity gate */}
                <div className="flex items-center gap-2 shrink-0">
                  {integrityVerified ? (
                    <div className="flex items-center gap-1.5 px-3 py-1.5 bg-positive-bg border border-positive-border text-positive text-xs font-mono">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>INTEGRITY VERIFIED (SHA-256 MATCH)</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 px-3 py-1.5 bg-critical-bg border border-critical-border text-critical text-xs font-mono">
                      <XCircle className="w-4 h-4" />
                      <span>INTEGRITY MISMATCH / FAIL-CLOSED</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-3 border-t border-line flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <p className="text-xs text-ink-3">
                  Trigger an immutable forensic re-analysis of the same verified
                  capture artifact to test deterministic reproducibility.
                </p>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={async () => {
                    setIsReanalyzing(true);
                    setReanalysisError(null);
                    try {
                      const res = await api.analyses.reAnalyze(analysisId);
                      setReanalysisResult(res);
                      refetchReplay();
                    } catch (err: any) {
                      setReanalysisError(err?.message || "Re-analysis failed");
                    } finally {
                      setIsReanalyzing(false);
                    }
                  }}
                  disabled={isReanalyzing || !integrityVerified}
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 ${isReanalyzing ? "animate-spin" : ""}`}
                  />
                  <span>
                    {isReanalyzing ? "Re-Analyzing…" : "Trigger Forensic Re-Analysis"}
                  </span>
                </Button>
              </div>

              {reanalysisResult && (
                <div
                  role="status"
                  aria-live="polite"
                  className="p-3 bg-positive-bg border border-positive-border text-xs font-mono text-positive flex flex-wrap items-center justify-between gap-2"
                >
                  <div>
                    <span className="font-semibold">
                      Re-Analysis Created: {reanalysisResult.child_analysis_id}
                    </span>
                    <span className="ml-2">({reanalysisResult.comparison_status})</span>
                  </div>
                  <a
                    href={`/analyses/${reanalysisResult.child_analysis_id}/evidence`}
                    className="flex items-center gap-1 underline hover:opacity-80"
                  >
                    <span>Open Child Run</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              )}

              {reanalysisError && (
                <div
                  role="alert"
                  className="p-3 bg-critical-bg border border-critical-border text-xs font-mono text-critical"
                >
                  <span className="font-semibold">Re-Analysis Error:</span>{" "}
                  {reanalysisError}
                </div>
              )}
            </div>

            {/* Deterministic comparison / diff */}
            <div className="border border-line bg-panel p-4 space-y-3">
              <div className="flex items-center justify-between gap-3 border-b border-line pb-2">
                <span className={labelCls}>Comparison outcome</span>
                {replayLineage?.latest_comparison ? (
                  <span
                    className={`px-2 py-0.5 font-semibold uppercase text-[11px] border ${
                      comparisonMatch
                        ? "bg-positive-bg text-positive border-positive-border"
                        : "bg-critical-bg text-critical border-critical-border"
                    }`}
                  >
                    {replayLineage.latest_comparison.comparison_status}
                  </span>
                ) : (
                  <span className="px-2 py-0.5 font-semibold uppercase text-[11px] bg-info-bg text-ink-2 border border-info-border">
                    NOT RECORDED
                  </span>
                )}
              </div>

              {replayLineage?.latest_comparison ? (
                <div className="space-y-3 text-xs font-mono">
                  <p className="text-ink-2 leading-relaxed">
                    {replayLineage.latest_comparison.summary}
                  </p>

                  {replayLineage.latest_comparison.differences && (
                    <div className="p-3 bg-critical-bg border border-critical-border space-y-1">
                      <span className="font-semibold text-critical uppercase text-[11px] block">
                        Discrepancies Detected
                      </span>
                      <pre className="text-[11px] overflow-x-auto text-ink-2 whitespace-pre-wrap break-all">
                        {JSON.stringify(
                          replayLineage.latest_comparison.differences,
                          null,
                          2
                        )}
                      </pre>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState
                  compact
                  icon={<History />}
                  title="No comparison recorded yet"
                  description="Trigger a forensic re-analysis above to compute itemized deterministic diffs."
                />
              )}
            </div>
          </div>
        </Section>
      ) : (
        /* ---------- Graph / table / textual traversal ---------- */
        <Section
          index="§2"
          title="Evidence Views"
          description="Interactive provenance DAG with tabular and textual fallbacks. Select a node to inspect its forensic properties."
        >
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
            <div className={selectedNode ? "lg:col-span-8" : "lg:col-span-12"}>
              {viewMode === "table" ? (
                <div className="border border-line bg-panel p-4">
                  <div className="flex items-baseline justify-between gap-3 pb-3">
                    <span className="text-[13px] font-semibold text-ink">
                      Evidence nodes ({nodeCount})
                    </span>
                    <span className="text-[11px] font-mono text-ink-3">
                      Select a row to inspect
                    </span>
                  </div>

                  {nodeCount > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left font-mono text-xs border border-line">
                        <thead className="bg-panel-2 border-b border-line uppercase text-[11px] tracking-wide text-ink-3">
                          <tr>
                            <th className="px-3 py-2 font-semibold text-ink">Tier / Type</th>
                            <th className="px-3 py-2 font-semibold text-ink">Label</th>
                            <th className="px-3 py-2 font-semibold text-ink">Entity ID</th>
                            <th className="px-3 py-2 font-semibold text-ink">Properties</th>
                            <th className="px-3 py-2 font-semibold text-ink text-right">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line bg-panel">
                          {(evidence?.nodes || []).map((n) => {
                            const nodeType = n.node_type || (n as any).type || (n as any).data?.nodeType || "NODE";
                            const label = n.label || (n as any).data?.labelRaw || (n as any).data?.label || n.id;
                            const entityId = n.entity_id || (n as any).data?.entityId || (n as any).data?.subject_id || (n as any).data?.rule_id || n.id;
                            const props = n.properties || (n as any).data?.properties || (n as any).data || {};
                            const isSelected = selectedNode?.id === n.id;

                            return (
                              <tr
                                key={n.id}
                                onClick={() => setSelectedNode({ id: n.id, node_type: nodeType, label, entity_id: entityId, properties: props })}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter" || e.key === " ") {
                                    e.preventDefault();
                                    setSelectedNode({ id: n.id, node_type: nodeType, label, entity_id: entityId, properties: props });
                                  }
                                }}
                                tabIndex={0}
                                className={`cursor-pointer transition-colors focus-visible:outline-2 focus-visible:outline-accent ${
                                  isSelected
                                    ? "bg-accent-soft font-semibold border-l-2 border-l-accent"
                                    : "hover:bg-panel-2 border-l-2 border-l-transparent"
                                }`}
                              >
                                <td className="px-3 py-2">
                                  <span className="px-1.5 py-0.5 text-[11px] font-bold bg-panel-3 border border-line text-ink-2 uppercase">
                                    {nodeType}
                                  </span>
                                </td>
                                <td className="px-3 py-2 font-semibold text-ink">{label}</td>
                                <td className="px-3 py-2 text-ink-3">{entityId}</td>
                                <td className="px-3 py-2 text-[11px] text-ink-3 truncate max-w-xs">
                                  {props && Object.keys(props).length > 0
                                    ? Object.keys(props).join(", ")
                                    : "None"}
                                </td>
                                <td className="px-3 py-2 text-right">
                                  <span className="text-[11px] text-accent-ink font-semibold uppercase">
                                    Inspect →
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <EmptyState
                      compact
                      title="No evidence nodes reconstructed for this run."
                    />
                  )}
                </div>
              ) : viewMode === "graph" ? (
                <div className="border border-line bg-panel">
                  <div className="px-4 py-2.5 border-b border-line flex items-center justify-between gap-3">
                    <span className="text-[13px] font-semibold text-ink">
                      Evidence Lineage DAG
                    </span>
                    <span className="text-[11px] font-mono text-ink-3">
                      {nodeCount} nodes · {(evidence?.edges || []).length} links
                    </span>
                  </div>
                  <div
                    className="h-[600px] w-full border-t border-line bg-panel"
                    role="region"
                    aria-label="Evidence lineage graph"
                  >
                    {nodes.length > 0 ? (
                      <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onNodeClick={onNodeClick}
                        fitView
                        fitViewOptions={{
                          padding: 0.15,
                          duration: prefersReducedMotion() ? 0 : 750,
                          ease: easeOutExpo,
                        }}
                      >
                        <Background color="var(--color-line-strong)" gap={16} />
                        <Controls />
                        <MiniMap
                          nodeColor="var(--color-accent)"
                          maskColor="rgba(127,127,127,0.18)"
                          style={{
                            background: "var(--color-panel-2)",
                            border: "1px solid var(--color-line)",
                          }}
                        />
                      </ReactFlow>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center">
                        <EmptyState
                          compact
                          icon={<Layers />}
                          title="No evidence nodes reconstructed for this run."
                        />
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="border border-line bg-panel p-4">
                  <div className="flex items-baseline justify-between gap-3 pb-3 border-b border-line">
                    <span className="text-[13px] font-semibold text-ink">
                      Textual evidence lineage ({nodeCount})
                    </span>
                    <span className="text-[11px] font-mono text-ink-3">
                      Select a node to inspect
                    </span>
                  </div>

                  {nodeCount > 0 ? (
                    <div className="divide-y divide-line">
                      {(evidence?.nodes || []).map((node) => {
                        const nodeType = node.node_type || (node as any).type || (node as any).data?.nodeType || "NODE";
                        const label = node.label || (node as any).data?.labelRaw || (node as any).data?.label || node.id;
                        const entityId = node.entity_id || (node as any).data?.entityId || (node as any).data?.subject_id || (node as any).data?.rule_id || node.id;
                        const props = node.properties || (node as any).data?.properties || (node as any).data || {};
                        const isSelected = selectedNode?.id === node.id;

                        return (
                          <button
                            type="button"
                            key={node.id}
                            onClick={() => setSelectedNode({ id: node.id, node_type: nodeType, label, entity_id: entityId, properties: props })}
                            aria-pressed={isSelected}
                            className={`w-full py-3 px-2 flex items-center justify-between gap-3 text-left border-l-2 transition-colors ${
                              isSelected
                                ? "bg-accent-soft border-l-accent"
                                : "border-l-transparent hover:bg-panel-2"
                            }`}
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="px-1.5 py-0.5 font-mono text-[11px] bg-panel-3 border border-line text-ink-2 uppercase">
                                  {nodeType}
                                </span>
                                <span className="font-mono text-ink truncate">{label}</span>
                              </div>
                              <div className="text-[11px] font-mono text-ink-3">
                                Entity ID: {entityId}
                              </div>
                            </div>
                            <ArrowRight className="w-4 h-4 text-ink-3 shrink-0" />
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <EmptyState
                      compact
                      title="No evidence nodes reconstructed for this run."
                    />
                  )}
                </div>
              )}

              {/* Evidence gaps */}
              {computedGaps.length > 0 && (
                <div className="border border-line bg-panel p-4 mt-4 space-y-2">
                  <div className="flex items-baseline justify-between gap-3 pb-1">
                    <span className="text-[13px] font-semibold text-ink">
                      Identified evidence gaps &amp; missing handshake context ({computedGaps.length})
                    </span>
                  </div>
                  {computedGaps.map((gap: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 bg-panel-2 border border-line flex items-start gap-3 text-xs"
                    >
                      <HelpCircle className="w-4 h-4 text-medium shrink-0 mt-0.5" />
                      <div>
                        <span className="font-mono font-semibold text-ink">
                          Fact required: {gap.fact_name}
                        </span>
                        <p className="text-ink-3 mt-0.5 leading-relaxed">{gap.rationale}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right Inspector Drawer */}
            {selectedNode && (
              <div className="lg:col-span-4">
                <InspectorDrawer
                  isOpen={!!selectedNode}
                  onClose={() => setSelectedNode(null)}
                  title={selectedNode?.label || selectedNode?.id || "Evidence Node"}
                  subtitle={`Node Type: ${(selectedNode?.node_type || (selectedNode as any)?.type || (selectedNode as any)?.data?.node_type || "NODE").toUpperCase()}`}
                  badge={
                    <span className="px-1.5 py-0.5 font-mono text-[11px] bg-panel-2 border border-line text-ink-2">
                      {selectedNode?.node_type || (selectedNode as any)?.type || "NODE"}
                    </span>
                  }
                >
                  <div className="space-y-4 font-mono text-xs">
                    <div className="p-3 bg-panel-2 border border-line space-y-1">
                      <div className="text-[11px] text-ink-3 uppercase tracking-wide font-semibold">
                        Entity Reference
                      </div>
                      <CopyableValue value={selectedNode.entity_id} label="Entity ID" />
                    </div>

                    <div>
                      <span className="text-[11px] uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                        Forensic Properties
                      </span>
                      <div className="p-3 bg-panel-2 border border-line space-y-1">
                        {selectedNode.properties ? (
                          Object.entries(selectedNode.properties).map(([k, v]) => (
                            <div
                              key={k}
                              className="flex justify-between gap-2 py-0.5 border-b border-line last:border-0"
                            >
                              <span className="text-ink-3">{k}:</span>
                              <span className="font-semibold text-ink truncate max-w-[160px]">
                                {typeof v === "object" ? JSON.stringify(v) : String(v)}
                              </span>
                            </div>
                          ))
                        ) : (
                          <span className="text-ink-3">No extra properties recorded.</span>
                        )}
                      </div>
                    </div>

                    {/* Byte Offset Verification */}
                    <div className="p-2.5 bg-panel-2 border border-line text-[11px] text-ink-3">
                      <span className="font-semibold block text-ink mb-0.5">
                        Byte Offset Status:
                      </span>
                      {selectedNode.properties?.byte_offset !== undefined
                        ? `0x${Number(selectedNode.properties.byte_offset).toString(16)} (Validated)`
                        : "Byte offset unavailable from parser layer (zero-hallucination guarantee)."}
                    </div>
                  </div>
                </InspectorDrawer>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* §3 Lineage / provenance progressive disclosure */}
      <Section
        index="§3"
        title="Provenance & Lineage Detail"
        description="Analysis lineage, child replay runs, version pins, toolchain, and metrics verification."
      >
        <div className="border border-line bg-panel">
          <button
            type="button"
            onClick={() => setShowProvenance((v) => !v)}
            aria-expanded={showProvenance}
            className="w-full flex items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-panel-2 transition-colors"
          >
            <span className="text-[13px] font-semibold text-ink">
              Lineage · child runs · version pins · metrics verification
            </span>
            <ChevronRight
              className={`w-4 h-4 text-ink-3 shrink-0 transition-transform ${
                showProvenance ? "rotate-90" : ""
              }`}
            />
          </button>

          {showProvenance && (
            <div className="border-t border-line p-4 grid grid-cols-1 md:grid-cols-2 gap-5 items-start">
              {/* Analysis lineage */}
              <div className="space-y-2">
                <h4 className={labelCls}>Analysis Lineage</h4>
                <div className="border border-line bg-panel-2 font-mono text-xs space-y-1 p-3">
                  <div className="flex justify-between gap-3">
                    <span className="text-ink-3">This run</span>
                    <span className="font-semibold text-ink">{analysisId}</span>
                  </div>
                  <div className="flex justify-between gap-3">
                    <span className="text-ink-3">Replay mode</span>
                    <span className="font-semibold text-ink">
                      {replayLineage?.replay_mode || "ORIGINAL_INGESTION"}
                    </span>
                  </div>
                  <div className="flex justify-between gap-3">
                    <span className="text-ink-3">Parent analysis</span>
                    {replayLineage?.parent_analysis_id ? (
                      <a
                        href={`/analyses/${replayLineage.parent_analysis_id}/evidence`}
                        className="text-accent-ink hover:underline flex items-center gap-1"
                      >
                        <span>{replayLineage.parent_analysis_id}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span className="text-ink-3 italic">
                        None (Root capture ingestion)
                      </span>
                    )}
                  </div>
                  <div className="flex justify-between gap-3">
                    <span className="text-ink-3">Capture</span>
                    <span className="font-semibold text-ink">
                      {replayLineage?.capture_filename || "unknown"}
                    </span>
                  </div>
                  <div className="flex justify-between gap-3 items-center">
                    <span className="text-ink-3">SHA-256</span>
                    {replayLineage?.capture_sha256 ? (
                      <CopyableValue
                        value={replayLineage.capture_sha256}
                        truncate
                        label="Capture SHA-256"
                      />
                    ) : (
                      <span className="text-ink-3">unknown</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Child replay runs */}
              <div className="space-y-2">
                <h4 className={labelCls}>
                  Child Replay Runs ({replayLineage?.child_runs?.length || 0})
                </h4>
                {replayLineage?.child_runs && replayLineage.child_runs.length > 0 ? (
                  <div className="divide-y divide-line border border-line">
                    {replayLineage.child_runs.map((c) => (
                      <div
                        key={c.analysis_id}
                        className="p-2.5 flex items-center justify-between gap-2 font-mono text-xs"
                      >
                        <div className="min-w-0">
                          <span className="font-semibold text-ink">
                            {c.analysis_id.slice(0, 8)}...
                          </span>
                          <span className="ml-2 text-[11px] text-ink-3">
                            [{c.replay_mode || "REPLAY"}]
                          </span>
                        </div>
                        <a
                          href={`/analyses/${c.analysis_id}/evidence`}
                          className="text-accent-ink hover:underline flex items-center gap-1 shrink-0"
                        >
                          <span>Inspect</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    compact
                    title="No child replays generated yet."
                  />
                )}
              </div>

              {/* Version pins & toolchain */}
              <div className="space-y-2">
                <h4 className={labelCls}>Version Pins &amp; Toolchain</h4>
                <div className="border border-line bg-panel-2 font-mono text-xs">
                  {[
                    [
                      "Parser",
                      `${replayLineage?.version_pins?.parser_engine ?? "—"} (${
                        replayLineage?.version_pins?.parser_version ?? "—"
                      })`,
                    ],
                    ["Schema", replayLineage?.version_pins?.schema_version ?? "—"],
                    [
                      "Policy",
                      replayLineage?.version_pins?.pinned_policy_bundle_version ||
                        "NIST SP 800-77 (Default)",
                    ],
                    [
                      "ML Classifier",
                      replayLineage?.version_pins?.pinned_model_bundle_id || "NOT_CONFIGURED",
                    ],
                  ].map(([k, v], idx, arr) => (
                    <div
                      key={k}
                      className={`flex justify-between gap-3 px-3 py-1.5 ${
                        idx < arr.length - 1 ? "border-b border-line" : ""
                      }`}
                    >
                      <span className="text-ink-3">{k}</span>
                      <span className="font-semibold text-ink text-right">{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Metrics verification */}
              <div className="space-y-2">
                <h4 className={labelCls}>Metrics Verification</h4>
                {replayLineage?.latest_comparison?.metrics &&
                Object.keys(replayLineage.latest_comparison.metrics).length > 0 ? (
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(replayLineage.latest_comparison.metrics).map(([k, v]) => (
                      <div
                        key={k}
                        className="p-2 bg-panel-2 border border-line"
                      >
                        <span className="text-[11px] text-ink-3 uppercase block">
                          {k.replace(/_/g, " ")}
                        </span>
                        <span className="font-semibold text-ink text-sm font-mono">
                          {String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    compact
                    title="No comparison metrics recorded yet."
                    description="Trigger a forensic re-analysis from the Replay Lineage tab to compute itemized metric verification."
                  />
                )}
              </div>
            </div>
          )}
        </div>
      </Section>
    </div>
  );
}

export default function EvidenceExplorerPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);

  return (
    <Suspense
      fallback={
        <div role="status" aria-live="polite">
          <EmptyState compact title="Loading forensic evidence explorer…" />
        </div>
      }
    >
      <EvidenceExplorerContent analysisId={analysisId} />
    </Suspense>
  );
}
