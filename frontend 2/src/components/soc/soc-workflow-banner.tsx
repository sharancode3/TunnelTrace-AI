"use client";

import React from "react";
import Link from "next/link";
import {
  Radio,
  Layers,
  ShieldAlert,
  FileSearch,
  History,
  FileText,
  Server,
  Activity,
  CheckCircle2,
} from "lucide-react";
import { useAnalysis } from "@/lib/analysis-context";

export type SocWorkflowStep = 1 | 2 | 3 | 4 | 5 | 6 | 7;

interface SocWorkflowBannerProps {
  activeStep: SocWorkflowStep;
  analysisId?: string | null;
  gatewayIdentity?: string | null;
  gatewayIp?: string | null;
  authorizedScope?: string | null;
  evidenceCoverage?: number | any | null;
  sensorFreshness?: "HEALTHY" | "DEGRADED" | "STALE" | "UNKNOWN" | null;
}

interface StepDef {
  step: SocWorkflowStep;
  title: string;
  shortLabel: string;
  icon: React.ComponentType<{ className?: string }>;
  getHref: (props: SocWorkflowBannerProps) => string;
}

const WORKFLOW_STEPS: StepDef[] = [
  {
    step: 1,
    title: "1. Scope & Telemetry",
    shortLabel: "1. Telemetry",
    icon: Radio,
    getHref: () => "/monitoring",
  },
  {
    step: 2,
    title: "2. Gateway Registry",
    shortLabel: "2. Gateways",
    icon: Server,
    getHref: (p) => (p.gatewayIdentity ? `/monitoring?tab=gateways&gateway=${encodeURIComponent(p.gatewayIdentity)}` : "/monitoring?tab=gateways"),
  },
  {
    step: 3,
    title: "3. Event Timeline",
    shortLabel: "3. Timeline",
    icon: Layers,
    getHref: (p) => (p.gatewayIdentity ? `/monitoring?tab=timeline&gateway=${encodeURIComponent(p.gatewayIdentity)}` : "/monitoring?tab=timeline"),
  },
  {
    step: 4,
    title: "4. Findings Triage",
    shortLabel: "4. Findings",
    icon: ShieldAlert,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/security` : "/analyses?action=select_run"),
  },
  {
    step: 5,
    title: "5. Evidence DAG",
    shortLabel: "5. Evidence",
    icon: FileSearch,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/evidence` : "/analyses?action=select_run"),
  },
  {
    step: 6,
    title: "6. Replay & Lineage",
    shortLabel: "6. Replay",
    icon: History,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/evidence?view=replay` : "/analyses?action=select_run"),
  },
  {
    step: 7,
    title: "7. Audit Report",
    shortLabel: "7. Report",
    icon: FileText,
    getHref: (p) => (p.analysisId ? `/analyses/${p.analysisId}/reports` : "/analyses?action=select_run"),
  },
];

export function SocWorkflowBanner({
  activeStep,
  analysisId,
  gatewayIdentity,
  gatewayIp,
  authorizedScope,
  evidenceCoverage,
  sensorFreshness,
}: SocWorkflowBannerProps) {
  const { activeAnalysisId } = useAnalysis();
  const effectiveAnalysisId = analysisId ?? activeAnalysisId;

  return (
    <div className="border border-line bg-panel p-3 space-y-2.5 font-mono text-xs shadow-sm">
      {/* Top Bar: Title & Active Context Badges */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-line pb-2">
        <div className="flex items-center space-x-2">
          <Activity className="w-4 h-4 text-accent-ink" />
          <span className="font-semibold uppercase tracking-[0.06em] text-ink">
            SOC Analyst Investigation Workflow
          </span>
          <span className="text-[11px] px-1.5 py-0.5 border border-line bg-panel-2 text-ink-2 uppercase tracking-[0.06em]">
            OPERATOR WORKFLOW
          </span>
        </div>

        {/* Dynamic Context Chips */}
        <div className="flex items-center flex-wrap gap-2 text-[11px]">
          {gatewayIdentity && (
            <div className="flex items-center space-x-1 px-2 py-0.5 border border-line bg-panel-2">
              <Server className="w-3 h-3 text-ink-2" />
              <span className="text-ink-2">Asset:</span>
              <span className="font-semibold text-ink">{gatewayIdentity}</span>
              {gatewayIp && <span className="text-ink-2">({gatewayIp})</span>}
            </div>
          )}

          {authorizedScope && (
            <div className="px-2 py-0.5 border border-line bg-panel-2">
              <span className="text-ink-2">Scope: </span>
              <span className="font-semibold text-ink">{authorizedScope}</span>
            </div>
          )}

          {sensorFreshness && (
            <div
              className={`px-2 py-0.5 border text-[11px] font-semibold uppercase tracking-[0.06em] ${
                sensorFreshness === "HEALTHY"
                  ? "border-positive-border bg-positive-bg text-positive"
                  : sensorFreshness === "STALE"
                  ? "border-medium-border bg-medium-bg text-medium"
                  : sensorFreshness === "DEGRADED"
                  ? "border-high-border bg-high-bg text-high"
                  : "border-line bg-panel-2 text-ink-2"
              }`}
            >
              Sensor: {sensorFreshness}
            </div>
          )}

          {(() => {
            const num =
              typeof evidenceCoverage === "number"
                ? evidenceCoverage
                : typeof evidenceCoverage === "object" && evidenceCoverage !== null && "coverage_percentage" in evidenceCoverage
                ? Number(evidenceCoverage.coverage_percentage)
                : null;
            if (num === null || isNaN(num)) return null;
            const pct = num <= 1 ? (num * 100).toFixed(0) : num.toFixed(0);
            return (
              <div className="px-2 py-0.5 border border-line bg-panel-2">
                <span className="text-ink-2">Evidence: </span>
                <span className="font-semibold text-ink">{pct}%</span>
              </div>
            );
          })()}

          {effectiveAnalysisId && (
            <div className="px-2 py-0.5 border border-line bg-panel-2">
              <span className="text-ink-2">Run: </span>
              <span className="font-semibold text-accent-ink">{effectiveAnalysisId.slice(0, 8)}...</span>
            </div>
          )}
        </div>
      </div>

      {/* Workflow Stepper */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-1">
        {WORKFLOW_STEPS.map((s) => {
          const Icon = s.icon;
          const isActive = s.step === activeStep;
          const isPassed = s.step < activeStep;
          const href = s.getHref({
            activeStep,
            analysisId: effectiveAnalysisId,
            gatewayIdentity,
            gatewayIp,
            authorizedScope,
            evidenceCoverage,
            sensorFreshness,
          });

          return (
            <Link
              key={s.step}
              href={href}
              className={`flex items-center space-x-1.5 px-2 py-1.5 border transition-all text-[11px] ${
                isActive
                  ? "bg-accent-press text-on-accent border-accent-press font-semibold shadow-sm"
                  : isPassed
                  ? "bg-panel-2 text-ink border-line hover:border-line-strong"
                  : "bg-transparent text-ink-2 border-line hover:border-line-strong hover:text-ink"
              }`}
            >
              {isPassed ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-positive shrink-0" />
              ) : (
                <Icon className="w-3.5 h-3.5 shrink-0" />
              )}
              <span className="truncate">{s.shortLabel}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
