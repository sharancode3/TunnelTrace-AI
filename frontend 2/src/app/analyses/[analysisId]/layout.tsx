"use client";
import React, { use, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight, ChevronDown, Clock3, RefreshCw } from "lucide-react";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge } from "@/components/ui/badge";
import { CopyableValue } from "@/components/ui/table";
import { formatCoverage } from "@/lib/format";
import { ScoreDisplay } from "@/components/ui/score-display";
import { api } from "@/lib/api/client";

const stages = [
  ["VALIDATION", "Validate"], ["PROTOCOL_DISSECTION", "Dissect"], ["SA_RECONSTRUCTION", "Reconstruct"],
  ["FLOW_RECONSTRUCTION", "Flows"], ["ML_INFERENCE", "Classify"], ["SECURITY_ASSESSMENT", "Assess"],
  ["SCORING_EVIDENCE", "Evidence"], ["COMPLETED", "Complete"],
] as const;
const pages = [["Overview", "overview"], ["Security", "security"], ["Protocol", "protocol"], ["Associations", "sas"], ["Traffic", "traffic"], ["Threats", "threats"], ["Evidence", "evidence"], ["Compliance", "compliance"], ["Remediation", "remediation"], ["Reports", "reports"], ["Analyst", "ai-analyst"]] as const;

export default function AnalysisLayout({ children, params }: { children: React.ReactNode; params: Promise<{ analysisId: string }> }) {
  const { analysisId } = use(params); const pathname = usePathname() || "";
  const { activeAnalysisId, setActiveAnalysisId, analysis, overview, refetch } = useAnalysis();
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [navOpen, setNavOpen] = useState(false);
  useEffect(() => { if (analysisId && activeAnalysisId !== analysisId) setActiveAnalysisId(analysisId); }, [analysisId, activeAnalysisId, setActiveAnalysisId]);
  const capture = overview?.capture; const filename = capture?.filename || analysis?.capture_filename || "Recorded capture";
  const runStatus = analysis?.status || overview?.analysis?.status || "UNKNOWN";
  const currentIndex = analysis?.current_stage ? stages.findIndex(([id]) => id === analysis.current_stage) : -1;
  const finished = runStatus === "COMPLETED"; const progress = finished ? stages.length : Math.max(0, currentIndex + 1);
  const recompute = async () => { setBusy(true); setError(null); try { await api.analyses.recompute(analysisId); refetch(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Recompute failed"); } finally { setBusy(false); } };
  return <div className="page-wrap pb-14 pt-5 sm:pt-8">
    {analysis?.is_outdated_version && <div className="mb-6 flex flex-wrap items-center justify-between gap-3 border-y border-medium-border bg-medium-bg px-4 py-3 text-sm"><p className="text-ink-2">This run used pipeline v{analysis.pipeline_version || "1.0.0"}. Recompute to use the current evidence and compliance rules.</p><button onClick={recompute} disabled={busy} className="inline-flex items-center gap-2 font-medium underline underline-offset-4"><RefreshCw className={`h-4 w-4 ${busy ? "animate-spin" : ""}`} />{busy ? "Recomputing…" : "Recompute run"}</button></div>}
    {error && <p role="alert" className="mb-4 text-sm text-critical">{error}</p>}
    <header className="border-y border-line py-5 sm:py-7">
      <div className="flex flex-wrap items-start justify-between gap-5">
        <div className="min-w-0"><h1 className="editorial-title max-w-[24ch] break-words text-3xl sm:text-5xl">{filename}</h1><div className="micro-label mt-3 text-ink-3">Investigation · {analysis?.pipeline_version ? `Pipeline ${analysis.pipeline_version}` : "IPsec capture"}</div><div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-ink-3"><span className="flex items-center gap-2"><span className="micro-label">Run</span><CopyableValue value={analysisId} label="Investigation ID" truncate /></span>{capture?.packet_count != null && <span className="font-mono tabular-nums">{capture.packet_count.toLocaleString()} packets</span>}{capture?.sha256 && <span className="font-mono">SHA-256 · {capture.sha256.slice(0, 12)}…</span>}</div></div>
        <div className="flex items-center gap-4">{overview?.security_posture && <div className="border-l border-line pl-4"><div className="micro-label text-ink-3">Posture</div><ScoreDisplay score={overview.security_posture.score} coverage={overview.security_posture.evidence_coverage} riskTier={overview.security_posture.aggregate_risk_tier} status={overview.security_posture.status} size="sm" /></div>}<StatusBadge status={runStatus} /></div>
      </div>
      <div className="mt-6 grid grid-cols-4 gap-x-4 gap-y-3 sm:grid-cols-8" aria-label="Analysis pipeline progress">
        {stages.map(([id, label], index) => { const skipped = id === "ML_INFERENCE" && (overview?.traffic_summary?.ml_run_status === "NOT_CONFIGURED" || (overview?.traffic_summary?.classified_flows === 0 && !overview?.traffic_summary?.model_bundle_id)); const complete = (finished || progress > index) && !skipped; const active = analysis?.current_stage === id; return <div key={id} className="min-w-0"><div className={`h-[3px] ${complete || active ? "bg-accent-press" : "bg-line-strong"}`} /><div className={`mt-2 truncate font-mono text-[.6rem] uppercase tracking-[.03em] ${complete || active ? "text-ink-2" : "text-ink-3"}`}>{skipped ? "ML skipped" : label}</div></div>; })}
      </div>
      <div className="mt-3 flex items-center justify-between gap-4 text-[.68rem] text-ink-3"><span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{analysis?.current_stage ? `Current stage · ${analysis.current_stage.replaceAll("_", " ")}` : finished ? "Pipeline complete" : "Pipeline state unavailable"}</span>{overview?.security_posture?.evidence_coverage != null && <span className="font-mono">{formatCoverage(overview.security_posture.evidence_coverage)} evidence coverage</span>}</div>
    </header>
    <div className="border-b border-line">
      <button type="button" onClick={() => setNavOpen((value) => !value)} aria-expanded={navOpen} className="flex w-full items-center justify-between py-3 text-left"><span className="micro-label text-ink-3">Investigation index <span className="ml-2 font-sans normal-case tracking-normal text-ink-2">Open a record</span></span><ChevronDown className={`h-4 w-4 transition-transform ${navOpen ? "rotate-180" : ""}`} /></button>
      <div className="nav-expand" data-open={navOpen} aria-hidden={!navOpen}><nav aria-label="Investigation pages" className="grid grid-cols-2 gap-x-7 pb-4 sm:grid-cols-3 lg:grid-cols-4">{pages.map(([label, slug]) => { const href = `/analyses/${analysisId}/${slug}`; const current = pathname === href; return <Link key={slug} href={href} aria-current={current ? "page" : undefined} tabIndex={navOpen ? 0 : -1} className={`flex items-center justify-between border-t border-line py-3 text-sm transition-colors hover:text-ink ${current ? "font-medium text-ink" : "text-ink-2"}`}>{label}{current ? <span className="h-1.5 w-1.5 rounded-full bg-accent-press" /> : <ArrowUpRight className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-100" />}</Link>; })}</nav></div>
    </div>
    <div className="pt-8 sm:pt-10">{children}</div>
  </div>;
}
