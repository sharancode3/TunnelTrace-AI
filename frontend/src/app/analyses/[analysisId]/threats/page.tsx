"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { SeverityBadge, EvidenceStateBadge } from "@/components/ui/badge";
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
import { ThreatInstanceDTO } from "@/lib/api/types";
import { Grid, Shield, AlertTriangle, AlertCircle, ShieldAlert } from "lucide-react";

export default function ThreatMatrixPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedThreat, setSelectedThreat] = useState<ThreatInstanceDTO | null>(null);

  const {
    data: threats,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["threats", analysisId],
    queryFn: () => api.analyses.getThreats(analysisId),
  });

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Mapping security findings against deterministic threat catalog (THR-001..THR-008) and MITRE ATT&CK...
      </div>
    );
  }

  if (isError || !threats) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load threat matrix: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <Grid className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Threat Matrix & Adversary Tactics Mapping
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage-8 deterministic catalog mappings correlating protocol vulnerabilities to MITRE ATT&CK Enterprise techniques and NIST controls.
        </p>
      </div>

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className={selectedThreat ? "lg:col-span-8" : "lg:col-span-12"}>
          <Card title={`Active Threat Catalog Mappings (${threats.length})`}>
            {threats.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Threat ID</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Risk Tier</TableHead>
                    <TableHead>Likelihood / Impact</TableHead>
                    <TableHead>MITRE ATT&CK</TableHead>
                    <TableHead>NIST Control</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {threats.map((threat) => (
                    <TableRow
                      key={threat.threat_id}
                      onClick={() => setSelectedThreat(threat)}
                      isSelected={selectedThreat?.threat_id === threat.threat_id}
                    >
                      <TableCell mono>
                        <span className="font-bold text-neutral-900 dark:text-white">
                          {threat.threat_id}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-bold text-neutral-900 dark:text-white">
                          {threat.title}
                        </span>
                      </TableCell>
                      <TableCell mono className="text-neutral-500 uppercase text-[11px]">
                        {threat.category}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={threat.risk_tier} />
                      </TableCell>
                      <TableCell mono className="text-neutral-600 dark:text-neutral-300 text-[11px]">
                        {threat.likelihood} / {threat.impact}
                      </TableCell>
                      <TableCell mono className="text-[#FF3D00] font-semibold">
                        {threat.mitre_technique_id}
                      </TableCell>
                      <TableCell mono className="text-neutral-500 text-[11px]">
                        {threat.nist_control}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="py-12 text-center font-mono text-xs text-neutral-500">
                No active threats mapped from current findings.
              </div>
            )}
          </Card>
        </div>

        {/* Right Contextual Inspector */}
        {selectedThreat && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedThreat}
              onClose={() => setSelectedThreat(null)}
              title={selectedThreat.title}
              subtitle={`Threat Catalog: ${selectedThreat.threat_id}`}
              badge={<SeverityBadge severity={selectedThreat.risk_tier} />}
            >
              <div className="space-y-4 font-mono text-xs">
                {/* Risk Parameters */}
                <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Likelihood:</span>
                    <span className="font-bold text-neutral-900 dark:text-white">
                      {selectedThreat.likelihood}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Impact:</span>
                    <span className="font-bold text-neutral-900 dark:text-white">
                      {selectedThreat.impact}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Category:</span>
                    <span>{selectedThreat.category}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-neutral-500">Evidence State:</span>
                    <span>{selectedThreat.evidence_state}</span>
                  </div>
                </div>

                {/* Standards & Frameworks */}
                <div>
                  <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                    Defensive & Adversary Frameworks
                  </span>
                  <div className="space-y-2">
                    <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                      <div className="text-[10px] text-neutral-400 uppercase">
                        MITRE ATT&CK Technique
                      </div>
                      <div className="text-sm font-bold text-[#FF3D00] mt-0.5">
                        {selectedThreat.mitre_technique_id}
                      </div>
                    </div>

                    <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                      <div className="text-[10px] text-neutral-400 uppercase">
                        NIST SP 800-53 Security Control
                      </div>
                      <div className="text-sm font-bold text-neutral-900 dark:text-white mt-0.5">
                        {selectedThreat.nist_control}
                      </div>
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
