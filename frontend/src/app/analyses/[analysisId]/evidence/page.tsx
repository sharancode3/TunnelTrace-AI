"use client";

import React, { use, useState, useEffect } from "react";
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
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { CopyableValue } from "@/components/ui/table";
import {
  FileSearch,
  AlertCircle,
  Network,
  ListTree,
  AlertTriangle,
  HelpCircle,
  ArrowRight,
  Shield,
  Layers,
} from "lucide-react";

export default function EvidenceExplorerPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const searchParams = useSearchParams();
  const highlightedFindingId = searchParams.get("findingId");

  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [viewMode, setViewMode] = useState<"graph" | "lineage">("graph");

  const {
    data: evidence,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["evidence-graph", analysisId],
    queryFn: () => api.analyses.getEvidenceGraph(analysisId),
  });

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (evidence && evidence.nodes && evidence.edges) {
      const typeColors: Record<string, string> = {
        finding: "#E11D48",
        rule: "#D97706",
        fact: "#2563EB",
        observation: "#059669",
        packet: "#7C3AED",
        capture: "#4B5563",
      };

      const formattedNodes: Node[] = evidence.nodes.map((n, idx) => {
        const isHighlight =
          highlightedFindingId && n.entity_id === highlightedFindingId;

        return {
          id: n.id,
          type: "default",
          data: { label: `${n.node_type.toUpperCase()}\n${n.label}` },
          position: {
            x: (idx % 3) * 260 + 40,
            y: Math.floor(idx / 3) * 140 + 40,
          },
          style: {
            background: isHighlight ? "#FF3D00" : "#1A1A1E",
            color: "#FFFFFF",
            border: isHighlight ? "2px solid #FFFFFF" : `1px solid ${typeColors[n.node_type] || "#555"}`,
            borderRadius: "0px",
            fontFamily: "monospace",
            fontSize: "11px",
            padding: "8px",
            width: 210,
          },
        };
      });

      const formattedEdges: Edge[] = evidence.edges.map((e, idx) => ({
        id: `e-${idx}`,
        source: e.source_id,
        target: e.target_id,
        label: e.relation_type,
        style: { stroke: "#71717A", strokeWidth: 1.5 },
      }));

      setNodes(formattedNodes);
      setEdges(formattedEdges);
    }
  }, [evidence, highlightedFindingId, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    const rawNode = evidence?.nodes?.find((n) => n.id === node.id);
    if (rawNode) {
      setSelectedNode(rawNode);
    }
  };

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Assembling cryptographic evidence DAG and tracing forensic packet provenance...
      </div>
    );
  }

  if (isError || !evidence) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load evidence graph: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileSearch className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Forensic Evidence Explorer & Lineage DAG
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            Trace deterministic lineage: Finding → Policy Rule → Security Fact → SA/Flow → Frame → Capture SHA-256.
          </p>
        </div>

        {/* View Switcher */}
        <div className="flex items-center space-x-1 border border-neutral-300 dark:border-neutral-800 p-0.5 bg-white dark:bg-[#141416]">
          <button
            onClick={() => setViewMode("graph")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "graph"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Interactive DAG</span>
          </button>
          <button
            onClick={() => setViewMode("lineage")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "lineage"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <ListTree className="w-3.5 h-3.5" />
            <span>Textual Traversal</span>
          </button>
        </div>
      </div>

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className={selectedNode ? "lg:col-span-8" : "lg:col-span-12"}>
          {viewMode === "graph" ? (
            <Card title="Evidence Lineage DAG (React Flow)">
              <div className="h-[600px] w-full border border-neutral-200 dark:border-neutral-800 bg-[#0E0E10]">
                {nodes.length > 0 ? (
                  <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onNodeClick={onNodeClick}
                    fitView
                  >
                    <Background color="#333" gap={16} />
                    <Controls />
                    <MiniMap
                      nodeColor="#FF3D00"
                      maskColor="rgba(0,0,0,0.7)"
                      style={{ background: "#111" }}
                    />
                  </ReactFlow>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center font-mono text-xs text-neutral-500 space-y-2">
                    <Layers className="w-8 h-8 text-neutral-600" />
                    <p>No evidence nodes reconstructed for this run.</p>
                  </div>
                )}
              </div>
            </Card>
          ) : (
            <Card title={`Textual Evidence Lineage Nodes (${evidence.nodes.length})`}>
              <div className="divide-y divide-neutral-200 dark:divide-neutral-800 text-xs">
                {evidence.nodes.map((node) => (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`py-3 px-2 flex items-center justify-between cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-900/60 ${
                      selectedNode?.id === node.id ? "bg-neutral-100 dark:bg-neutral-800/80 font-bold border-l-2 border-l-[#FF3D00]" : ""
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-200 dark:bg-neutral-800 uppercase">
                          {node.node_type}
                        </span>
                        <span className="font-mono text-neutral-900 dark:text-white">
                          {node.label}
                        </span>
                      </div>
                      <div className="text-[10px] font-mono text-neutral-500">
                        Entity ID: {node.entity_id}
                      </div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-neutral-400" />
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Evidence Gaps Section */}
          {evidence.evidence_gaps && evidence.evidence_gaps.length > 0 && (
            <div className="mt-6">
              <Card
                title={`Identified Evidence Gaps & Missing Handshake Context (${evidence.evidence_gaps.length})`}
                variant="subtle"
              >
                <div className="space-y-2">
                  {evidence.evidence_gaps.map((gap, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 flex items-start space-x-3 text-xs"
                    >
                      <HelpCircle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-mono font-bold text-neutral-900 dark:text-white">
                          Fact Required: {gap.fact_name}
                        </span>
                        <p className="text-neutral-500 mt-0.5">{gap.rationale}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}
        </div>

        {/* Right Inspector Drawer */}
        {selectedNode && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedNode}
              onClose={() => setSelectedNode(null)}
              title={selectedNode.label}
              subtitle={`Node Type: ${selectedNode.node_type.toUpperCase()}`}
              badge={
                <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                  {selectedNode.node_type}
                </span>
              }
            >
              <div className="space-y-4 font-mono text-xs">
                <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1">
                  <div className="text-[10px] text-neutral-400 uppercase">Entity Reference</div>
                  <CopyableValue value={selectedNode.entity_id} label="Entity ID" />
                </div>

                <div>
                  <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                    Forensic Properties
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1">
                    {selectedNode.properties ? (
                      Object.entries(selectedNode.properties).map(([k, v]) => (
                        <div key={k} className="flex justify-between py-0.5 border-b border-neutral-100 dark:border-neutral-800 last:border-0">
                          <span className="text-neutral-500">{k}:</span>
                          <span className="font-bold truncate max-w-[160px]">
                            {typeof v === "object" ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))
                    ) : (
                      <span className="text-neutral-500">No extra properties recorded.</span>
                    )}
                  </div>
                </div>

                {/* Byte Offset Verification */}
                <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] text-neutral-500">
                  <span className="font-bold block text-neutral-800 dark:text-neutral-200 mb-0.5">
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
    </div>
  );
}
