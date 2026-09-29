"use client";

import React, { use, useState, useEffect } from "react";
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
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { EvidenceStateBadge, StatusBadge, StateText } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { ChildSecurityAssociationDTO } from "@/lib/api/types";
import { easeOutExpo, prefersReducedMotion } from "@/lib/motion";
import {
  Table as TableIcon,
  Network,
  AlertTriangle,
  Layers,
} from "lucide-react";

export default function SecurityAssociationExplorerPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [selectedSa, setSelectedSa] = useState<ChildSecurityAssociationDTO | null>(null);
  const [selectedNode, setSelectedNode] = useState<{ id: string; type: string; label: string; data?: any } | null>(null);

  // Fetch SA List (tabular data)
  const {
    data: saList,
    isLoading: isListLoading,
    isError: isListError,
    refetch: refetchList,
  } = useQuery({
    queryKey: ["sas-list", analysisId],
    queryFn: () => api.analyses.getSas(analysisId),
  });

  // Fetch SA Graph (nodes and edges)
  const {
    data: saGraph,
    isLoading: isGraphLoading,
    isError: isGraphError,
    refetch: refetchGraph,
  } = useQuery({
    queryKey: ["sas-graph", analysisId],
    queryFn: () => api.analyses.getSaGraph(analysisId),
  });

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (saGraph && saGraph.nodes && saGraph.edges) {
      // Classify node tier for hierarchical left-to-right topology (0..4)
      const getTier = (type: string, id: string): number => {
        const t = (type || "").toLowerCase();
        const nid = (id || "").toLowerCase();
        if (t.includes("peer") || nid.includes("peer")) return 0;
        if (t.includes("session") || nid.includes("session")) return 1;
        if (t.includes("ike") && !t.includes("child")) return 2;
        if (t.includes("child") || nid.includes("child")) return 3;
        if (t.includes("flow") || nid.includes("flow") || t.includes("esp")) return 4;
        return 2;
      };

      const NODE_WIDTH = 220;
      const HORIZ_GAP = 180; // 180px gap provides clearance for full edge labels
      const VERT_STEP = 150;

      const tierCounts: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };

      // Semantic palette: resolves per theme (light/dark) through CSS variables
      const typeStyles: Record<
        number,
        { border: string; bg: string; badge: string; text: string }
      > = {
        0: { border: "var(--color-low)", bg: "var(--color-low-bg)", badge: "PEER", text: "var(--color-low)" },
        1: { border: "var(--color-info)", bg: "var(--color-info-bg)", badge: "IKE SESSION", text: "var(--color-ink-2)" },
        2: { border: "var(--color-medium)", bg: "var(--color-medium-bg)", badge: "IKE SA", text: "var(--color-medium)" },
        3: { border: "var(--color-positive)", bg: "var(--color-positive-bg)", badge: "CHILD SA", text: "var(--color-positive)" },
        4: { border: "var(--color-high)", bg: "var(--color-high-bg)", badge: "ESP FLOW", text: "var(--color-high)" },
      };

      // Unobserved node set for styling connected edges
      const unobservedNodeIds = new Set<string>();
      saGraph.nodes.forEach((n) => {
        const ev = n.data?.evidence_state || (n as any).evidence_state;
        if (ev === "NOT_OBSERVED" || n.id.includes("unobserved")) {
          unobservedNodeIds.add(n.id);
        }
      });

      const formattedNodes: Node[] = saGraph.nodes.map((n) => {
        const tier = getTier(n.type, n.id);
        const yIndex = tierCounts[tier] || 0;
        tierCounts[tier] = yIndex + 1;

        // Strictly fixed 5-column layout: Peer (col 0) -> IKE Session (col 1) -> IKE SA (col 2) -> Child SA (col 3) -> ESP Flow (col 4)
        const xPos = 40 + tier * (NODE_WIDTH + HORIZ_GAP);
        const yPos = 40 + yIndex * VERT_STEP;

        const evState = n.data?.evidence_state || (n as any).evidence_state || "";
        const isNotObserved = evState === "NOT_OBSERVED" || n.id.includes("unobserved");
        const isInferred = evState.includes("INFERRED");

        const baseStyle = typeStyles[tier] || typeStyles[2];

        // Determine border, bg, and badge based on evidence state
        let border = baseStyle.border;
        let borderStyle = "solid";
        let bg = "var(--color-panel)";
        let badgeBg = baseStyle.bg;
        let badgeText = baseStyle.text;
        let badgeLabel = baseStyle.badge;

        if (isNotObserved) {
          border = "var(--color-ink-3)";
          borderStyle = "dashed";
          bg = "var(--color-panel-2)";
          badgeBg = "var(--color-panel-3)";
          badgeText = "var(--color-ink-3)";
          badgeLabel = `${baseStyle.badge} · NOT OBSERVED`;
        } else if (isInferred) {
          border = "var(--color-medium)";
          badgeBg = "var(--color-medium-bg)";
          badgeText = "var(--color-medium)";
          badgeLabel = `${baseStyle.badge} · INFERRED`;
        }

        return {
          id: n.id,
          type: "default",
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="text-left font-mono">
                <div className="flex items-center justify-between mb-1 pb-1 border-b border-line">
                  <span
                    className="text-[11px] font-bold px-1.5 py-0.5 tracking-wider uppercase"
                    style={{ backgroundColor: badgeBg, color: badgeText, border: `1px solid ${border}` }}
                  >
                    {badgeLabel}
                  </span>
                  {isNotObserved && (
                    <span className="text-[11px] text-ink-3 italic">missing</span>
                  )}
                </div>
                <div
                  className={`font-semibold text-xs leading-tight ${
                    isNotObserved ? "text-ink-3 italic" : "text-ink"
                  }`}
                >
                  {n.label || n.type}
                </div>
                {n.data?.reason ? (
                  <div className="text-[11px] text-medium mt-1 leading-snug">
                    {n.data.reason}
                  </div>
                ) : (
                  <div className="text-[11px] text-ink-3 font-mono mt-1 break-all" title={n.id}>
                    {n.id.startsWith("0x")
                      ? `${n.id.slice(0, 10)}...${n.id.slice(-4)}`
                      : n.id.length > 20
                      ? `${n.id.slice(0, 16)}...`
                      : n.id}
                  </div>
                )}
              </div>
            ),
            rawNode: n,
          },
          position: { x: xPos, y: yPos },
          style: {
            background: bg,
            color: isNotObserved ? "var(--color-ink-3)" : "var(--color-ink)",
            border: `2px ${borderStyle} ${border}`,
            borderRadius: 0,
            fontFamily: "monospace",
            fontSize: "11px",
            padding: "10px 12px",
            width: NODE_WIDTH,
            opacity: isNotObserved ? 0.85 : 1.0,
          },
        };
      });

      const formattedEdges: Edge[] = saGraph.edges.map((e) => {
        const isDashed = unobservedNodeIds.has(e.source) || unobservedNodeIds.has(e.target);
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          type: "smoothstep",
          style: {
            stroke: isDashed ? "var(--color-line-strong)" : "var(--color-ink-3)",
            strokeWidth: isDashed ? 1.5 : 2,
            strokeDasharray: isDashed ? "5,5" : undefined,
          },
          labelStyle: {
            fill: "var(--color-ink)",
            fontSize: 10,
            fontFamily: "ui-monospace, monospace",
            fontWeight: 700,
            letterSpacing: "0.04em",
          },
          labelBgStyle: {
            fill: "var(--color-panel)",
            fillOpacity: 0.98,
            stroke: "var(--color-line-strong)",
            strokeWidth: 1.5,
            rx: 0,
            ry: 0,
          },
          labelBgPadding: [8, 4] as [number, number],
        };
      });

      setNodes(formattedNodes);
      setEdges(formattedEdges);
    }
  }, [saGraph, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    const raw = (node.data as any)?.rawNode;
    setSelectedNode(raw || { id: node.id, type: node.type || "node", label: String(node.id) });

    const matched = (saList || []).find(
      (sa) => sa.id === node.id || sa.inbound_spi === node.id || sa.outbound_spi === node.id || node.id.includes(sa.id)
    );
    setSelectedSa(matched || null);
  };

  const isLoading = isListLoading || isGraphLoading;

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState
          compact
          title="Reconstructing SA topology…"
          description="Traversing the SA session graph and directional SPI associations."
        />
      </div>
    );
  }

  if (isListError || isGraphError) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load security associations"
          description="The SA list or topology graph could not be retrieved for this run."
          action={
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                refetchList();
                refetchGraph();
              }}
            >
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  const hierarchyChip = "px-1.5 py-0.5 border";

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight">
            Security Associations
          </h1>
          <p className="text-[13px] text-ink-2">
            Directional SAs, inbound/outbound SPI pairing, Child SA lifecycle, and
            endpoint accounting. Nodes not captured in the PCAP are shown with
            dashed borders as NOT OBSERVED.
          </p>
        </div>

        <div
          role="group"
          aria-label="SA view mode"
          className="flex items-center gap-0.5 border border-line bg-panel p-0.5 self-start sm:self-auto"
        >
          <button
            type="button"
            onClick={() => setViewMode("graph")}
            aria-pressed={viewMode === "graph"}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === "graph"
                ? "bg-accent-press text-on-accent"
                : "text-ink-3 hover:text-ink hover:bg-panel-2"
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Topology Graph</span>
          </button>
          <button
            type="button"
            onClick={() => setViewMode("table")}
            aria-pressed={viewMode === "table"}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === "table"
                ? "bg-accent-press text-on-accent"
                : "text-ink-3 hover:text-ink hover:bg-panel-2"
            }`}
          >
            <TableIcon className="w-3.5 h-3.5" />
            <span>SA Table</span>
          </button>
        </div>
      </div>

      <Section
        index="§1"
        title={viewMode === "graph" ? "SA Topology DAG" : "Child Security Associations"}
        description={
          viewMode === "graph"
            ? "Five-level hierarchy: peer → IKE session → IKE SA → Child SA → ESP flow. Click a node to inspect it."
            : "Every reconstructed Child SA with its SPI pair, algorithms, lifecycle state, and observation window."
        }
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          <div className={selectedSa || selectedNode ? "lg:col-span-8" : "lg:col-span-12"}>
            {viewMode === "graph" ? (
              <div className="border border-line bg-panel">
                {/* Legend */}
                <div className="p-3 bg-panel-2 border-b border-line space-y-2 text-[11px] font-mono">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-ink-3 font-semibold uppercase tracking-wide">
                        5-level hierarchy:
                      </span>
                      <span className={`${hierarchyChip} bg-low-bg text-low border-low-border`}>
                        1. Peer
                      </span>
                      <span className="text-ink-3">→</span>
                      <span className={`${hierarchyChip} bg-info-bg text-ink-2 border-info-border`}>
                        2. IKE Session
                      </span>
                      <span className="text-ink-3">→</span>
                      <span className={`${hierarchyChip} bg-medium-bg text-medium border-medium-border`}>
                        3. IKE SA
                      </span>
                      <span className="text-ink-3">→</span>
                      <span className={`${hierarchyChip} bg-positive-bg text-positive border-positive-border`}>
                        4. Child SA
                      </span>
                      <span className="text-ink-3">→</span>
                      <span className={`${hierarchyChip} bg-high-bg text-high border-high-border`}>
                        5. ESP Flow
                      </span>
                    </div>
                    <span className="text-ink-3">Click a node for inspection details</span>
                  </div>

                  <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-line">
                    <span className="text-ink-3 font-semibold uppercase tracking-wide">
                      Evidence states:
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 bg-positive-bg border border-positive-border inline-block" />
                      <span className="text-ink-2">Observed in PCAP</span>
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 bg-medium-bg border border-medium-border inline-block" />
                      <span className="text-ink-2">Inferred / Synthesized</span>
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 bg-panel-3 border border-dashed border-ink-3 inline-block" />
                      <span className="text-ink-2">Not Observed (Missing from Capture)</span>
                    </span>
                  </div>
                </div>

                <div
                  className="h-[620px] w-full border-t border-line bg-panel relative"
                  role="region"
                  aria-label="Security association topology graph"
                >
                  {saGraph && saGraph.nodes && saGraph.nodes.length > 0 ? (
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
                      minZoom={0.2}
                      maxZoom={2.0}
                    >
                      <Background color="var(--color-line-strong)" gap={20} size={1} />
                      <Controls className="bg-panel border border-line" />
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
                    <EmptyState
                      icon={<Layers />}
                      title="No Security Associations reconstructed"
                      description="This capture artifact contains no IKE negotiation or ESP encrypted flows. Security Association hierarchies are only formed when IPsec handshake or data packets are observed."
                    />
                  )}
                </div>
              </div>
            ) : (
              <div className="border border-line bg-panel p-4">
                <div className="flex items-baseline justify-between gap-3 pb-3">
                  <span className="text-[13px] font-semibold text-ink">
                    Child SAs ({saList?.length || 0})
                  </span>
                  <span className="text-[11px] font-mono text-ink-3">
                    Inbound/outbound SPI pair per Child SA
                  </span>
                </div>

                {saList && saList.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <tr>
                        <TableHead>SA ID</TableHead>
                        <TableHead>Endpoints</TableHead>
                        <TableHead>Protocol</TableHead>
                        <TableHead>Inbound SPI</TableHead>
                        <TableHead>Outbound SPI</TableHead>
                        <TableHead>Mode</TableHead>
                        <TableHead>Algorithms</TableHead>
                        <TableHead>PFS</TableHead>
                        <TableHead>Lifecycle</TableHead>
                        <TableHead>Observed</TableHead>
                        <TableHead>Evidence</TableHead>
                      </tr>
                    </TableHeader>
                    <TableBody>
                      {saList.map((sa) => (
                        <TableRow
                          key={sa.id}
                          onClick={() => {
                            setSelectedSa(sa);
                            setSelectedNode(null);
                          }}
                          isSelected={selectedSa?.id === sa.id}
                        >
                          <TableCell mono>
                            <CopyableValue value={sa.id} truncate label="SA ID" />
                          </TableCell>
                          <TableCell mono className="text-ink-2 whitespace-nowrap">
                            {sa.src_ip && sa.dst_ip ? `${sa.src_ip} → ${sa.dst_ip}` : "—"}
                          </TableCell>
                          <TableCell mono>{sa.protocol}</TableCell>
                          <TableCell mono>
                            <CopyableValue value={sa.inbound_spi} label="Inbound SPI" />
                          </TableCell>
                          <TableCell mono>
                            <CopyableValue value={sa.outbound_spi} label="Outbound SPI" />
                          </TableCell>
                          <TableCell mono>
                            <span className="font-semibold text-ink">{sa.mode}</span>
                          </TableCell>
                          <TableCell mono>
                            <div className="font-semibold text-ink">
                              {sa.encryption_algorithm || "UNKNOWN"}
                            </div>
                            <div className="text-[11px] text-ink-3">
                              {sa.integrity_algorithm || "UNKNOWN"}
                            </div>
                          </TableCell>
                          <TableCell mono>
                            <div>{sa.pfs_status}</div>
                            {sa.pfs_dh_group && (
                              <div className="text-[11px] text-ink-3">DH {sa.pfs_dh_group}</div>
                            )}
                          </TableCell>
                          <TableCell>
                            <StatusBadge status={sa.lifecycle_state} />
                          </TableCell>
                          <TableCell mono className="text-[11px] text-ink-3 whitespace-nowrap">
                            <div>{sa.first_observed_at ? new Date(sa.first_observed_at).toLocaleString() : "—"}</div>
                            <div>{sa.last_observed_at ? new Date(sa.last_observed_at).toLocaleString() : "—"}</div>
                          </TableCell>
                          <TableCell>
                            <EvidenceStateBadge state={sa.evidence_state} />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <EmptyState
                    compact
                    icon={<Layers />}
                    title="No Child Security Associations found"
                    description="No Child SA could be reconstructed from this capture artifact."
                  />
                )}
              </div>
            )}
          </div>

          {/* Right Contextual Inspector */}
          {(selectedSa || selectedNode) && (
            <div className="lg:col-span-4">
              <InspectorDrawer
                isOpen={!!(selectedSa || selectedNode)}
                onClose={() => {
                  setSelectedSa(null);
                  setSelectedNode(null);
                }}
                title={
                  selectedSa
                    ? `SA: ${selectedSa.inbound_spi}`
                    : `${selectedNode?.type?.toUpperCase() || "NODE"}: ${selectedNode?.label || selectedNode?.id}`
                }
                subtitle={
                  selectedSa
                    ? `Protocol: ${selectedSa.protocol}`
                    : `ID: ${selectedNode?.id}`
                }
                badge={
                  <span className="px-1.5 py-0.5 font-mono text-[11px] bg-panel-2 border border-line text-ink-2">
                    {selectedSa?.lifecycle_state || selectedNode?.type?.toUpperCase() || "OBSERVED"}
                  </span>
                }
              >
                {selectedSa ? (
                  <div className="space-y-4">
                    <div>
                      <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                        SPI Identification
                      </span>
                      <div className="space-y-1 font-mono text-xs bg-panel-2 border border-line p-2.5">
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Inbound:</span>
                          <CopyableValue value={selectedSa.inbound_spi} label="Inbound SPI" />
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Outbound:</span>
                          <CopyableValue value={selectedSa.outbound_spi} label="Outbound SPI" />
                        </div>
                      </div>
                    </div>

                    <div>
                      <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                        Tunnel Mode &amp; Algorithms
                      </span>
                      <div className="space-y-1 font-mono text-xs bg-panel-2 border border-line p-2.5">
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Mode:</span>
                          <span className="font-semibold text-ink">{selectedSa.mode}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Encryption:</span>
                          <span className="text-ink">{selectedSa.encryption_algorithm || "UNKNOWN"}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Integrity:</span>
                          <span className="text-ink">{selectedSa.integrity_algorithm || "UNKNOWN"}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">PFS Status:</span>
                          <StateText value={selectedSa.pfs_status} className="font-semibold" />
                        </div>
                        {selectedSa.pfs_dh_group && (
                          <div className="flex justify-between gap-3">
                            <span className="text-ink-3">PFS DH Group:</span>
                            <span className="text-ink">{selectedSa.pfs_dh_group}</span>
                          </div>
                        )}
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Endpoints:</span>
                          <span className="text-ink">
                            {selectedSa.src_ip && selectedSa.dst_ip
                              ? `${selectedSa.src_ip} → ${selectedSa.dst_ip}`
                              : "—"}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                        Evidence Verification State
                      </span>
                      <div className="p-2.5 bg-panel-2 border border-line font-mono text-xs space-y-1">
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Mode Evidence:</span>
                          <span className="text-ink">{selectedSa.mode_evidence_state}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">PFS Evidence:</span>
                          <span className="text-ink">{selectedSa.pfs_evidence_state}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Overall:</span>
                          <span className="text-ink">{selectedSa.evidence_state}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : selectedNode ? (
                  <div className="space-y-4">
                    {(selectedNode.data?.evidence_state === "NOT_OBSERVED" || selectedNode.id.includes("unobserved")) && (
                      <div className="p-3 bg-panel-2 border-2 border-dashed border-line-strong text-xs font-mono space-y-1.5">
                        <div className="flex items-center gap-1.5 text-ink-2 font-bold uppercase text-[11px]">
                          <AlertTriangle className="w-4 h-4 text-ink-3" />
                          <span>Evidence Absent in PCAP</span>
                        </div>
                        <p className="text-ink-2 text-[11px] leading-relaxed">
                          {selectedNode.data?.reason || "This protocol tier was not captured in the packet trace. If the IKE handshake occurred before sniffing started, only subsequent ESP ciphertext flows are present."}
                        </p>
                        <div className="text-[11px] text-ink-3">
                          Status:{" "}
                          <span className="font-bold text-ink">
                            NOT ASSESSABLE FROM CAPTURE
                          </span>
                        </div>
                      </div>
                    )}

                    <div>
                      <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                        Node Properties
                      </span>
                      <div className="space-y-1 font-mono text-xs bg-panel-2 border border-line p-2.5">
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Identifier:</span>
                          <CopyableValue value={selectedNode.id} label="Node ID" />
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Type:</span>
                          <span className="font-semibold text-ink">{selectedNode.type}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-ink-3">Label:</span>
                          <span className="text-ink">{selectedNode.label}</span>
                        </div>
                      </div>
                    </div>

                    {selectedNode.data && (
                      <div>
                        <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                          Metadata &amp; Metrics
                        </span>
                        <div className="space-y-1 font-mono text-xs bg-panel-2 border border-line p-2.5">
                          {Object.entries(selectedNode.data).map(([k, v]) => (
                            <div key={k} className="flex justify-between gap-3 py-0.5 border-b border-line last:border-b-0">
                              <span className="text-ink-3">{k}:</span>
                              <span className="font-semibold text-ink">{String(v ?? "N/A")}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : null}
              </InspectorDrawer>
            </div>
          )}
        </div>
      </Section>
    </div>
  );
}
