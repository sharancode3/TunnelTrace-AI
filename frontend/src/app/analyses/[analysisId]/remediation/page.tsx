"use client";

import React, { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { SlidersHorizontal, AlertTriangle, ShieldCheck, Play, ArrowRight, Ban } from "lucide-react";

export default function RemediationTwinPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", analysisId],
    queryFn: () => api.analyses.getFindings(analysisId),
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <SlidersHorizontal className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Configuration Security Twin & Closed-Loop Remediation
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage 10 digital twin synthesis, strongSwan / IPsec configuration patching, and closed-loop verification.
        </p>
      </div>

      {/* Stage Boundary Warning Banner */}
      <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border-2 border-amber-500 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-2">
        <div className="flex items-center space-x-2 font-bold text-sm">
          <Ban className="w-5 h-5 text-amber-600 shrink-0" />
          <span>STAGE BOUNDARY: STAGE 10 NOT YET IMPLEMENTED</span>
        </div>
        <p>
          In accordance with the finalized roadmap, automated configuration simulation, strongSwan swanctl generation, live testbed application, and closed-loop verification belong to <strong>Stage 10</strong>.
        </p>
        <p className="text-amber-700 dark:text-amber-400">
          The deterministic remediation directives shown below are static recommendations derived from Stage-8 policy catalogs. Live simulation and patching controls remain strictly disabled to maintain zero-hallucination integrity.
        </p>
      </div>

      {/* Remediation Directives Catalog */}
      <div className="space-y-4">
        <h2 className="text-xs font-mono font-bold uppercase text-neutral-500 tracking-wider">
          Stage-8 Deterministic Remediation Directives ({findings?.length || 0})
        </h2>

        {isLoading ? (
          <div className="py-12 text-center font-mono text-xs text-neutral-500 animate-pulse">
            Loading deterministic remediation guidance...
          </div>
        ) : findings && findings.length > 0 ? (
          <div className="grid grid-cols-1 gap-4">
            {findings.map((f) => (
              <Card
                key={f.finding_id}
                title={`${f.rule_id} — ${f.title}`}
                badge={<SeverityBadge severity={f.severity} />}
              >
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-neutral-800 dark:text-neutral-200 whitespace-pre-wrap leading-relaxed">
                    {f.remediation_guidance}
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-neutral-200 dark:border-neutral-800">
                    <span className="text-neutral-400">Affected Target: {f.affected_entity}</span>
                    <button
                      disabled
                      className="px-3 py-1 bg-neutral-200 dark:bg-neutral-800 text-neutral-400 border border-neutral-300 dark:border-neutral-700 text-xs font-mono uppercase cursor-not-allowed"
                    >
                      Simulate Patch (Stage 10)
                    </button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center font-mono text-xs text-neutral-500">
            No remediation directives required for this analysis.
          </div>
        )}
      </div>
    </div>
  );
}
