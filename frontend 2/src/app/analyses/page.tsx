"use client";

import React, { useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Button, ButtonLink } from "@/components/ui/button";
import { StatusBadge, SeverityBadge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { EmptyState } from "@/components/ui/empty-state";
import { formatRelativeTime } from "@/lib/format";
import { ScoreDisplay } from "@/components/ui/score-display";
import {
  Plus,
  Search,
  Layers,
  AlertCircle,
  RefreshCw,
  Archive,
  Trash2,
  RotateCcw,
  ArrowRight,
  Loader2,
} from "lucide-react";

function AnalysesListContent() {
  const [search, setSearch] = useState("");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [leavingId, setLeavingId] = useState<string | null>(null);
  const searchParams = useSearchParams();
  const action = searchParams.get("action");

  const {
    data: analyses,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["analyses-list", includeArchived],
    queryFn: () => api.analyses.list(includeArchived),
  });

  const handleArchive = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setActionInProgress(id);
    try {
      await api.analyses.archive(id);
      if (!includeArchived) setLeavingId(id);
      await refetch();
    } catch (err: any) {
      alert(`Failed to archive run: ${err.message}`);
    } finally {
      setActionInProgress(null);
      setLeavingId(null);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (
      !window.confirm(
        `Permanently delete analysis run ${id.slice(0, 8)}? This cannot be undone.`
      )
    ) {
      return;
    }
    setActionInProgress(id);
    try {
      await api.analyses.delete(id);
      setLeavingId(id);
      await refetch();
    } catch (err: any) {
      alert(`Failed to delete run: ${err.message}`);
    } finally {
      setActionInProgress(null);
      setLeavingId(null);
    }
  };

  const filteredAnalyses = (analyses || []).filter((item) => {
    const q = search.toLowerCase();
    return (
      item.analysis_id.toLowerCase().includes(q) ||
      (item.capture_filename && item.capture_filename.toLowerCase().includes(q)) ||
      (item.capture_sha256 && item.capture_sha256.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-line pb-5">
        <div className="space-y-2 min-w-0">
          <div className="flex items-baseline gap-3">
            <h1 className="text-3xl font-semibold text-ink tracking-tight leading-none">
              Investigations
            </h1>
            {analyses && (
              <span className="text-3xl font-mono font-bold tabular-nums leading-none text-ink-3">
                {analyses.length}
              </span>
            )}
          </div>
          <p className="text-prose text-ink-2 max-w-[72ch]">
            Analysis runs and their security assessments.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => refetch()}>
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <ButtonLink href="/analyses/new" variant="primary" size="sm">
            <Plus className="w-3.5 h-3.5" />
            New Analysis
          </ButtonLink>
        </div>
      </div>

      {action === "select_run" && (
        <div className="p-3 bg-low-bg border border-low-border text-xs space-y-1">
          <div className="flex items-center gap-2 text-low font-medium">
            <Layers className="w-4 h-4 shrink-0" />
            <span>Select an active investigation</span>
          </div>
          <p className="text-ink-2">
            You requested a run-specific view outside an active investigation.
            Choose a run below, or ingest a new capture.
          </p>
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-ink-3 absolute left-2.5 top-2" />
          <input
            type="text"
            placeholder="Search by ID, filename, or SHA-256"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 h-8 text-[13px] bg-panel text-ink border border-line-strong placeholder:text-ink-3 font-mono focus:border-accent"
            aria-label="Search investigations"
          />
        </div>
        <label className="flex items-center gap-2 text-[13px] cursor-pointer text-ink-2 select-none">
          <input
            type="checkbox"
            checked={includeArchived}
            onChange={(e) => setIncludeArchived(e.target.checked)}
            className="accent-accent"
          />
          Show archived
        </label>
      </div>

      {isLoading ? (
        <EmptyState compact title="Loading investigations…" />
      ) : isError ? (
        <EmptyState
          icon={<AlertCircle />}
          title="Failed to load investigations"
          description={(error as any)?.message || "Unknown error"}
          action={
            <Button variant="secondary" size="sm" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : filteredAnalyses.length === 0 ? (
        <EmptyState
          icon={<Layers />}
          title="No investigations found"
          description="Ingest a capture to start your first analysis."
          action={
            <ButtonLink href="/analyses/new" variant="primary" size="sm">
              <Plus className="w-3.5 h-3.5" />
              New Analysis
            </ButtonLink>
          }
        />
      ) : (
        <Table>
          <TableHeader>
            <tr>
              <TableHead>Investigation</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Score</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Risk</TableHead>
              <TableHead>Run</TableHead>
              <TableHead className="text-right">Open</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </tr>
          </TableHeader>
          <TableBody>
            {filteredAnalyses.map((run) => (
              <TableRow
                key={run.analysis_id}
                className={
                  leavingId === run.analysis_id
                    ? "pointer-events-none opacity-0 transition-opacity duration-200 ease-[cubic-bezier(0.16,1,0.3,1)]"
                    : run.is_archived
                    ? "opacity-60"
                    : ""
                }
              >
                <TableCell>
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <Link
                        href={`/analyses/${run.analysis_id}/overview`}
                        className="font-medium text-ink hover:text-accent-ink transition-colors truncate max-w-[220px]"
                        title={run.capture_filename}
                      >
                        {run.capture_filename || "Unnamed capture"}
                      </Link>
                      {run.is_synthetic_demo && (
                        <span className="text-[11px] px-1 py-0.5 bg-medium-bg text-medium border border-medium-border uppercase">
                          Demo
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] font-mono text-ink-3">
                      <CopyableValue
                        value={run.analysis_id}
                        truncate
                        label="Analysis ID"
                      />
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col gap-1">
                    <StatusBadge status={run.status} />
                    {run.current_stage && (
                      <span className="text-[11px] font-mono text-ink-3">
                        {run.current_stage}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <ScoreDisplay
                    score={run.security_score}
                    coverage={run.coverage_percentage}
                    riskTier={run.risk_tier}
                    status={run.status}
                    size="sm"
                  />
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1.5 text-xs">
                    {run.critical_findings > 0 && (
                      <span className="text-critical font-medium">
                        {run.critical_findings} critical
                      </span>
                    )}
                    {run.high_findings > 0 && (
                      <span className="text-high font-medium">
                        {run.high_findings} high
                      </span>
                    )}
                    {run.critical_findings === 0 && run.high_findings === 0 && (
                      <span className="text-ink-3">None</span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={run.risk_tier || "UNKNOWN"} />
                </TableCell>
                <TableCell className="text-ink-3 font-mono text-xs">
                  {formatRelativeTime(run.created_at)}
                </TableCell>
                <TableCell className="text-right">
                  <Link
                    href={`/analyses/${run.analysis_id}/overview`}
                    className="inline-flex items-center gap-1 text-[13px] font-medium text-accent-ink hover:underline"
                  >
                    Open
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      onClick={(e) => handleArchive(run.analysis_id, e)}
                      disabled={actionInProgress === run.analysis_id}
                      className="p-1 text-ink-3 hover:text-ink border border-transparent hover:border-line transition-colors"
                      title={run.is_archived ? "Unarchive" : "Archive"}
                      aria-label={run.is_archived ? "Unarchive" : "Archive"}
                    >
                      {actionInProgress === run.analysis_id ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : run.is_archived ? (
                        <RotateCcw className="w-3.5 h-3.5" />
                      ) : (
                        <Archive className="w-3.5 h-3.5" />
                      )}
                    </button>
                    <button
                      onClick={(e) => handleDelete(run.analysis_id, e)}
                      disabled={actionInProgress === run.analysis_id}
                      className="p-1 text-ink-3 hover:text-critical border border-transparent hover:border-critical-border transition-colors"
                      title="Delete"
                      aria-label="Delete"
                    >
                      {actionInProgress === run.analysis_id ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Trash2 className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

export default function AnalysesListPage() {
  return (
    <Suspense
      fallback={<EmptyState compact title="Loading investigations…" />}
    >
      <AnalysesListContent />
    </Suspense>
  );
}
