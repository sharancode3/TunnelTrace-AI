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
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
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
import { ChildSecurityAssociationDTO } from "@/lib/api/types";
import {
  GitBranch,
  Table as TableIcon,
  Network,
  AlertCircle,
  Shield,
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

  // Fetch SA List (tabular data)
  const {
    data: saList,
    isLoading: isListLoading,
    isError: isListError,
  } = useQuery({
    queryKey: ["sas-list", analysisId],
    queryFn: () => api.analyses.getSas(analysisId),
  });

  // Fetch SA Graph (nodes and edges)
  const {
    data: saGraph,
    isLoading: isGraphLoading,
    isError: isGraphError,
  } = useQuery({
    queryKey: ["sas-graph", analysisId],
    queryFn: () => api.analyses.getSaGraph(analysisId),
  });

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (saGraph && saGraph.nodes && saGraph.edges) {
      const formattedNodes: Node[] = saGraph.nodes.map((n, idx) => ({
        id: n.id,
        type: "default",
        data: { label: `${n.label || n.type}\n${n.id.slice(0, 10)}...` },
        position: { x: (idx % 4) * 220 + 50, y: Math.floor(idx / 4) * 120 + 50 },
        style: {
          background: "#1E1E22",
          color: "#FFFFFF",
          border: "1px solid #3F3F46",
          borderRadius: "0px",
          fontFamily: "monospace",
          fontSize: "11px",
          padding: "8px",
          width: 180,
        },
      }));

      const formattedEdges: Edge[] = saGraph.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        style: { stroke: "#FF3D00", strokeWidth: 1.5 },
      }));

      setNodes(formattedNodes);
      setEdges(formattedEdges);
    }
  }, [saGraph, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    // Look up SA in saList if matches
    const matched = (saList || []).find(
      (sa) => sa.id === node.id || sa.inbound_spi === node.id || sa.outbound_spi === node.id
    );
    if (matched) {
      setSelectedSa(matched);
    }
  };

  const isLoading = isListLoading || isGraphLoading;

  return (
    <div className="space-y-6">
      {/* Header & View Mode Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <GitBranch className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Security Association (SA) Topology & Flow Explorer
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            Stage-4 deterministic reconstruction of IKE SAs, Child SAs, SPI pairs, and directional ESP encryption flows.
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
            <span>Topology Graph</span>
          </button>
          <button
            onClick={() => setViewMode("table")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "table"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <TableIcon className="w-3.5 h-3.5" />
            <span>SA Table Fallback</span>
          </button>
        </div>
      </div>

      {/* Main Workspace (12 cols: 8/7 cols canvas/table + 4/5 cols inspector) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className={selectedSa ? "lg:col-span-8" : "lg:col-span-12"}>
          {isLoading ? (
            <div className="py-24 text-center font-mono text-xs text-neutral-500 animate-pulse border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416]">
              Traversing SA session graph and directional SPI associations...
            </div>
          ) : viewMode === "graph" ? (
            <Card title="SA Topology DAG (React Flow)">
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
                    <p>No SA nodes reconstructed in graph for this capture.</p>
                  </div>
                )}
              </div>
            </Card>
          ) : (
            <Card title={`Child Security Associations (${saList?.length || 0})`}>
              {saList && saList.length > 0 ? (
                <Table>
                  <TableHeader>
                    <tr>
                      <TableHead>SA ID</TableHead>
                      <TableHead>Inbound SPI</TableHead>
                      <TableHead>Outbound SPI</TableHead>
                      <TableHead>Mode</TableHead>
                      <TableHead>Encryption</TableHead>
                      <TableHead>PFS</TableHead>
                      <TableHead>State</TableHead>
                    </tr>
                  </TableHeader>
                  <TableBody>
                    {saList.map((sa) => (
                      <TableRow
                        key={sa.id}
                        onClick={() => setSelectedSa(sa)}
                        isSelected={selectedSa?.id === sa.id}
                      >
                        <TableCell mono>
                          <CopyableValue value={sa.id} truncate label="SA ID" />
                        </TableCell>
                        <TableCell mono>
                          <CopyableValue value={sa.inbound_spi} label="Inbound SPI" />
                        </TableCell>
                        <TableCell mono>
                          <CopyableValue value={sa.outbound_spi} label="Outbound SPI" />
                        </TableCell>
                        <TableCell mono>
                          <span className="font-bold">{sa.mode}</span>
                        </TableCell>
                        <TableCell mono>{sa.encryption_algorithm || "UNKNOWN"}</TableCell>
                        <TableCell mono>{sa.pfs_status}</TableCell>
                        <TableCell mono className="text-neutral-400">
                          {sa.lifecycle_state}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="py-12 text-center font-mono text-xs text-neutral-500">
                  No Child Security Associations found.
                </div>
              )}
            </Card>
          )}
        </div>

        {/* Right Contextual Inspector */}
        {selectedSa && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedSa}
              onClose={() => setSelectedSa(null)}
              title={`SA: ${selectedSa.inbound_spi}`}
              subtitle={`Protocol: ${selectedSa.protocol}`}
              badge={
                <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                  {selectedSa.lifecycle_state}
                </span>
              }
            >
              <div className="space-y-4">
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    SPI Identification
                  </span>
                  <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Inbound:</span>
                      <CopyableValue value={selectedSa.inbound_spi} label="Inbound SPI" />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Outbound:</span>
                      <CopyableValue value={selectedSa.outbound_spi} label="Outbound SPI" />
                    </div>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Tunnel Mode & Algorithms
                  </span>
                  <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Mode:</span>
                      <span className="font-bold">{selectedSa.mode}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Encryption:</span>
                      <span>{selectedSa.encryption_algorithm || "UNKNOWN"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Integrity:</span>
                      <span>{selectedSa.integrity_algorithm || "UNKNOWN"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">PFS Status:</span>
                      <span>{selectedSa.pfs_status}</span>
                    </div>
                    {selectedSa.pfs_dh_group && (
                      <div className="flex justify-between">
                        <span className="text-neutral-500">PFS DH Group:</span>
                        <span>{selectedSa.pfs_dh_group}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Evidence Verification State
                  </span>
                  <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 font-mono text-xs space-y-1">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Mode Evidence:</span>
                      <span>{selectedSa.mode_evidence_state}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">PFS Evidence:</span>
                      <span>{selectedSa.pfs_evidence_state}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Overall:</span>
                      <span>{selectedSa.evidence_state}</span>
                    </div>
                  </div>
                </div>
              </div>
            </InspectorDrawer>
          </div>
        )}
      </div>
    </div>
  );
}
