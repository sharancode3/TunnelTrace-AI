"use client";

import React, { use, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { CopyableValue } from "@/components/ui/table";
import { ReportResponseDTO } from "@/lib/api/types";
import {
  FileText,
  Download,
  Eye,
  CheckCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  Printer,
  Shield,
  FileCode,
} from "lucide-react";

export default function ReportsWorkspacePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const queryClient = useQueryClient();

  const [previewReportId, setPreviewReportId] = useState<string | null>(null);
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);

  // List existing reports
  const {
    data: reportsData,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["reports-list", analysisId],
    queryFn: () => api.reports.list(analysisId),
  });

  // Generate Report Mutation
  const generateMutation = useMutation({
    mutationFn: (reportType: "EXECUTIVE" | "TECHNICAL") =>
      api.reports.generate(analysisId, reportType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports-list", analysisId] });
    },
  });

  const handlePreviewHtml = async (reportId: string) => {
    setPreviewReportId(reportId);
    setIsPreviewLoading(true);
    try {
      const html = await api.reports.getHtml(analysisId, reportId);
      setReportHtml(html);
    } catch {
      setReportHtml("<p style='color:red;'>Failed to load HTML report preview.</p>");
    } finally {
      setIsPreviewLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <FileText className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Publication-Grade Security & Forensics Reporting
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Deterministic server-side artifact generation from immutable analysis snapshots. Print CSS typography, SHA-256 provenance hashes, and zero LLM hallucination.
        </p>
      </div>

      {/* Generation Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Executive Summary Card */}
        <Card
          title="Executive Security Summary"
          badge={
            <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
              CISO / LEADERSHIP
            </span>
          }
        >
          <div className="space-y-3">
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              High-level strategic briefing communicating observed posture score, evidence coverage, material risks, standards compliance status, and deterministic recommended actions.
            </p>
            <div className="pt-2 flex items-center justify-between">
              <span className="text-[10px] font-mono text-neutral-400">
                Format: Canonical HTML + A4 Print PDF
              </span>
              <button
                disabled={generateMutation.isPending}
                onClick={() => generateMutation.mutate("EXECUTIVE")}
                className="flex items-center space-x-1.5 px-4 py-2 bg-[#FF3D00] hover:bg-[#e03600] disabled:bg-neutral-300 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>GENERATE EXECUTIVE</span>
              </button>
            </div>
          </div>
        </Card>

        {/* Technical Forensics Report Card */}
        <Card
          title="Technical Forensics & Audit Report"
          badge={
            <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
              SOC / AUDITOR
            </span>
          }
        >
          <div className="space-y-3">
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              Full forensic disclosure containing packet dissections, cryptographic transform tables, SPI pairs, ML flow feature attributions (TreeSHAP), rule evaluations, and complete evidence provenance hashes.
            </p>
            <div className="pt-2 flex items-center justify-between">
              <span className="text-[10px] font-mono text-neutral-400">
                Format: Canonical HTML + A4 Print PDF
              </span>
              <button
                disabled={generateMutation.isPending}
                onClick={() => generateMutation.mutate("TECHNICAL")}
                className="flex items-center space-x-1.5 px-4 py-2 bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 dark:text-neutral-900 disabled:bg-neutral-300 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>GENERATE TECHNICAL</span>
              </button>
            </div>
          </div>
        </Card>
      </div>

      {/* Generated Artifacts Table */}
      <Card
        title={`Generated Report Artifacts (${reportsData?.items?.length || 0})`}
        actions={
          <button
            onClick={() => refetch()}
            className="p-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-500"
            title="Refresh reports"
            aria-label="Refresh reports"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        }
      >
        {isLoading ? (
          <div className="py-8 text-center font-mono text-xs text-neutral-500 animate-pulse">
            Querying persisted report records from PostgreSQL...
          </div>
        ) : reportsData?.items && reportsData.items.length > 0 ? (
          <div className="divide-y divide-neutral-200 dark:divide-neutral-800">
            {reportsData.items.map((rep) => {
              const isHtmlAvailable =
                rep.status === "COMPLETED" ||
                rep.status === "PDF_FAILED_HTML_AVAILABLE";

              return (
                <div
                  key={rep.id}
                  className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono font-bold text-xs uppercase px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                        {rep.report_type}
                      </span>
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 border ${
                          rep.status === "COMPLETED"
                            ? "bg-emerald-100 text-emerald-900 border-emerald-500"
                            : rep.status === "PDF_FAILED_HTML_AVAILABLE"
                            ? "bg-amber-100 text-amber-900 border-amber-500"
                            : "bg-neutral-200 text-neutral-800 border-neutral-400"
                        }`}
                      >
                        {rep.status}
                      </span>
                      <span className="text-[11px] font-mono text-neutral-400">
                        Duration: {rep.generation_duration_ms ? `${rep.generation_duration_ms}ms` : "-"}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-neutral-500 space-y-0.5">
                      <div className="flex items-center space-x-2">
                        <span>Report ID:</span>
                        <CopyableValue value={rep.id} truncate label="Report ID" />
                      </div>
                      {rep.html_sha256 && (
                        <div className="flex items-center space-x-2">
                          <span>HTML SHA-256:</span>
                          <CopyableValue value={rep.html_sha256} truncate label="HTML SHA-256" />
                        </div>
                      )}
                      {rep.pdf_sha256 && (
                        <div className="flex items-center space-x-2">
                          <span>PDF SHA-256:</span>
                          <CopyableValue value={rep.pdf_sha256} truncate label="PDF SHA-256" />
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-2">
                    {isHtmlAvailable && (
                      <>
                        <button
                          onClick={() => handlePreviewHtml(rep.id)}
                          className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono font-semibold bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>PREVIEW HTML</span>
                        </button>

                        <a
                          href={api.reports.getDownloadUrl(analysisId, rep.id, "html")}
                          download
                          className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono font-semibold bg-white hover:bg-neutral-50 dark:bg-neutral-900 dark:hover:bg-neutral-800 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>HTML</span>
                        </a>
                      </>
                    )}

                    {rep.status === "COMPLETED" && rep.pdf_sha256 && (
                      <a
                        href={api.reports.getDownloadUrl(analysisId, rep.id, "pdf")}
                        download
                        className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono font-bold bg-[#FF3D00] hover:bg-[#e03600] text-white border border-[#FF3D00]"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>PDF</span>
                      </a>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="py-12 text-center font-mono text-xs text-neutral-500">
            No report artifacts generated yet for this analysis run.
          </div>
        )}
      </Card>

      {/* HTML Sandboxed Preview Modal / Pane */}
      {previewReportId && (
        <Card
          title="Safe Sandboxed Report HTML Preview"
          actions={
            <button
              onClick={() => {
                setPreviewReportId(null);
                setReportHtml(null);
              }}
              className="text-xs font-mono text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            >
              CLOSE PREVIEW
            </button>
          }
        >
          {isPreviewLoading ? (
            <div className="py-12 text-center font-mono text-xs text-neutral-500 animate-pulse">
              Retrieving sanitized HTML document from storage...
            </div>
          ) : reportHtml ? (
            <div className="border border-neutral-300 dark:border-neutral-800 bg-white">
              <iframe
                title="Report HTML Preview"
                srcDoc={reportHtml}
                sandbox="allow-same-origin"
                className="w-full h-[700px] border-0"
              />
            </div>
          ) : null}
        </Card>
      )}
    </div>
  );
}
