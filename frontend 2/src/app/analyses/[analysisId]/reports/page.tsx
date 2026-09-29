"use client";

import React, { use, useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Button, ButtonLink } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Section } from "@/components/ui/section";
import { EmptyState } from "@/components/ui/empty-state";
import { StatusBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
import { CopyableValue, Table, TableHeader, TableBody, TableRow, TableCell, TableHead } from "@/components/ui/table";
import {
  FileText,
  Download,
  Eye,
  RefreshCw,
  Printer,
  Shield,
  FileCode,
  FileSearch,
  CheckCircle2,
  FileSpreadsheet,
  Layers,
  X,
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
  const [generatingType, setGeneratingType] = useState<"EXECUTIVE" | "TECHNICAL" | null>(null);

  // Context queries
  const { data: analysisData } = useQuery({
    queryKey: ["analysis", analysisId],
    queryFn: () => api.analyses.get(analysisId),
  });

  const { data: securityScore } = useQuery({
    queryKey: ["security-score", analysisId],
    queryFn: () => api.analyses.getSecurityScore(analysisId),
  });

  const { data: replayLineage } = useQuery({
    queryKey: ["replay-lineage", analysisId],
    queryFn: () => api.analyses.getReplayLineage(analysisId),
  });

  // List existing reports
  const {
    data: reportsData,
    isLoading,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["reports-list", analysisId],
    queryFn: () => api.reports.list(analysisId),
  });

  // Generate Report Mutation
  const generateMutation = useMutation({
    mutationFn: (reportType: "EXECUTIVE" | "TECHNICAL") => {
      setGeneratingType(reportType);
      return api.reports.generate(analysisId, reportType);
    },
    onSuccess: (newReport) => {
      setGeneratingType(null);
      queryClient.invalidateQueries({ queryKey: ["reports-list", analysisId] });
      if (newReport?.id) {
        handlePreviewHtml(newReport.id);
      }
    },
    onError: () => {
      setGeneratingType(null);
    },
  });

  const handlePreviewHtml = async (reportId: string) => {
    setPreviewReportId(reportId);
    setIsPreviewLoading(true);
    try {
      const html = await api.reports.getHtml(analysisId, reportId);
      setReportHtml(html);
    } catch {
      setReportHtml("<p style='color:red; padding: 20px; font-family: monospace;'>Failed to load HTML report preview.</p>");
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const reports = reportsData?.items || [];
  const latestExecutive = reports.find((r) => r.report_type === "EXECUTIVE");
  const latestTechnical = reports.find((r) => r.report_type === "TECHNICAL");

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight">
            Security &amp; Forensics Reports
          </h1>
          <p className="text-[13px] text-ink-2">
            Publication-grade defense audit reports generated server-side for this investigation —
            executive summaries, cryptographic scorecards, and verifiable JSON/CSV exports.
          </p>
        </div>

        {/* Quick Context Links */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ButtonLink href={`/analyses/${analysisId}/security`} variant="secondary" size="sm">
            <Shield className="w-3.5 h-3.5" />
            <span>Findings</span>
          </ButtonLink>
          <ButtonLink href={`/analyses/${analysisId}/evidence`} variant="secondary" size="sm">
            <FileSearch className="w-3.5 h-3.5" />
            <span>Evidence DAG</span>
          </ButtonLink>
          <ButtonLink href={`/analyses/${analysisId}/ai-analyst`} variant="secondary" size="sm">
            <Layers className="w-3.5 h-3.5" />
            <span>AI Analyst</span>
          </ButtonLink>
        </div>
      </div>

      {/* §1 Target Scope & Verification Ribbon */}
      <Section index="§1" title="Investigation Context">
        <div className="border border-line bg-panel p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <div>
              <span className="text-[11px] text-ink-3 uppercase tracking-wide block">Capture File</span>
              <span className="font-mono font-semibold text-ink text-[13px]">
                {replayLineage?.capture_filename || analysisData?.capture_filename || analysisId.slice(0, 13)}
              </span>
            </div>
            <div className="h-6 w-px bg-line hidden sm:block" />
            <div>
              <span className="text-[11px] text-ink-3 uppercase tracking-wide block">Security Posture</span>
              <ScoreDisplay
                score={securityScore?.overall_score}
                coverage={
                  typeof securityScore?.evidence_coverage === "object" && securityScore?.evidence_coverage !== null && "coverage_percentage" in securityScore.evidence_coverage
                    ? (securityScore.evidence_coverage as any).coverage_percentage
                    : typeof securityScore?.evidence_coverage === "number"
                    ? securityScore.evidence_coverage
                    : (securityScore as any)?.coverage_percentage
                }
                status={securityScore?.status}
                size="sm"
              />
            </div>
            <div className="h-6 w-px bg-line hidden sm:block" />
            <div>
              <span className="text-[11px] text-ink-3 uppercase tracking-wide block">Evidence Integrity</span>
              {replayLineage?.capture_integrity_verified ? (
                <span className="text-positive font-semibold flex items-center gap-1 text-[13px]">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>SHA-256 VERIFIED</span>
                </span>
              ) : (
                <span className="text-ink-3 font-semibold text-[13px]">PRESERVED SNAPSHOT</span>
              )}
            </div>
          </div>

          <div className="text-[11px] text-ink-3 font-mono">
            Standards: NIST SP 800-77 Rev. 1 &bull; RFC 8247 &bull; RFC 8221
          </div>
        </div>
      </Section>

      {/* §2 Report Generation */}
      <Section index="§2" title="Generate Reports" description="Compile a sealed PDF artifact for this investigation. Generation runs server-side and the artifact is persisted to the report ledger below.">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Card 1: Executive Security Summary */}
          <div className="p-4 border border-line bg-panel flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-accent" />
                  <h3 className="font-semibold text-sm text-ink">
                    Executive Summary
                  </h3>
                </div>
                <span className="text-[11px] font-mono px-1.5 py-0.5 bg-panel-2 border border-line text-ink-3 uppercase tracking-wide">
                  Leadership / CISO
                </span>
              </div>
              <p className="text-[13px] text-ink-2 leading-relaxed">
                Strategic briefing with observed posture score, evidence coverage, compliance status against NIST/RFC standards, and prioritized remediation actions.
              </p>
            </div>

            <div className="space-y-2 pt-3 border-t border-line">
              <Button
                variant="primary"
                className="w-full"
                disabled={generateMutation.isPending}
                onClick={() => generateMutation.mutate("EXECUTIVE")}
                aria-live="polite"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>
                  {generatingType === "EXECUTIVE" ? "Compiling Executive PDF..." : "Generate Executive PDF"}
                </span>
              </Button>

              {latestExecutive && (
                <div className="flex items-center justify-between gap-2 text-xs text-ink-3 pt-1">
                  <span className="truncate font-mono">Latest: {new Date(latestExecutive.created_at).toLocaleTimeString()}</span>
                  <a
                    href={api.reports.getDownloadUrl(analysisId, latestExecutive.id, "pdf")}
                    download={`TunnelTrace_Executive_${analysisId.slice(0, 8)}.pdf`}
                    className="text-accent-ink hover:underline font-semibold shrink-0"
                  >
                    Download PDF &rarr;
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Card 2: Technical Forensics & Audit Report */}
          <div className="p-4 border border-line bg-panel flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-ink-2" />
                  <h3 className="font-semibold text-sm text-ink">
                    Technical Forensics
                  </h3>
                </div>
                <span className="text-[11px] font-mono px-1.5 py-0.5 bg-panel-2 border border-line text-ink-3 uppercase tracking-wide">
                  SOC / Auditor
                </span>
              </div>
              <p className="text-[13px] text-ink-2 leading-relaxed">
                Full forensic disclosure: packet dissections, cryptographic transform tables, SPI pairs, ML flow feature attributions, and evidence provenance hashes.
              </p>
            </div>

            <div className="space-y-2 pt-3 border-t border-line">
              <Button
                variant="secondary"
                className="w-full"
                disabled={generateMutation.isPending}
                onClick={() => generateMutation.mutate("TECHNICAL")}
                aria-live="polite"
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>
                  {generatingType === "TECHNICAL" ? "Compiling Technical PDF..." : "Generate Technical PDF"}
                </span>
              </Button>

              {latestTechnical && (
                <div className="flex items-center justify-between gap-2 text-xs text-ink-3 pt-1">
                  <span className="truncate font-mono">Latest: {new Date(latestTechnical.created_at).toLocaleTimeString()}</span>
                  <a
                    href={api.reports.getDownloadUrl(analysisId, latestTechnical.id, "pdf")}
                    download={`TunnelTrace_Technical_${analysisId.slice(0, 8)}.pdf`}
                    className="text-accent-ink hover:underline font-semibold shrink-0"
                  >
                    Download PDF &rarr;
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Card 3: Machine-Readable Data Exports */}
          <div className="p-4 border border-line bg-panel flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Download className="w-4 h-4 text-positive" />
                  <h3 className="font-semibold text-sm text-ink">
                    Data Exports
                  </h3>
                </div>
                <span className="text-[11px] font-mono px-1.5 py-0.5 bg-panel-2 border border-line text-ink-3 uppercase tracking-wide">
                  SIEM / JSON / CSV
                </span>
              </div>
              <p className="text-[13px] text-ink-2 leading-relaxed">
                Direct exports for SIEM ingestion, compliance records, and automated security ticketing workflows.
              </p>
            </div>

            <div className="space-y-2 pt-3 border-t border-line">
              <ButtonLink
                href={api.analyses.getExportManifestUrl(analysisId)}
                download={`tunneltrace_manifest_${analysisId.slice(0, 8)}.json`}
                variant="secondary"
                className="w-full"
              >
                <span className="inline-flex items-center gap-2">
                  <FileCode className="w-3.5 h-3.5 text-accent" />
                  <span>JSON Manifest</span>
                </span>
                <Download className="w-3.5 h-3.5 ml-auto" />
              </ButtonLink>

              <ButtonLink
                href={api.analyses.getExportFindingsCsvUrl(analysisId)}
                download={`tunneltrace_findings_${analysisId.slice(0, 8)}.csv`}
                variant="secondary"
                className="w-full"
              >
                <span className="inline-flex items-center gap-2">
                  <FileSpreadsheet className="w-3.5 h-3.5 text-positive" />
                  <span>CSV Findings</span>
                </span>
                <Download className="w-3.5 h-3.5 ml-auto" />
              </ButtonLink>
            </div>
          </div>
        </div>
      </Section>

      {/* §3 Generated Report Artifacts */}
      <Section
        index="§3"
        title={`Report History (${reports.length})`}
        description="Every sealed artifact generated for this investigation, with integrity digests and export actions."
        actions={
          <Button variant="secondary" size="sm" onClick={() => refetch()} aria-label="Refresh reports" title="Refresh reports">
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </Button>
        }
      >
        {isLoading ? (
          <div role="status" aria-live="polite">
            <EmptyState compact title="Querying persisted report records from database..." />
          </div>
        ) : reports.length > 0 ? (
          <Table>
            <TableHeader>
              <tr>
                <TableHead>Report Type</TableHead>
                <TableHead>Generated</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>SHA-256 Digest</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </tr>
            </TableHeader>
            <TableBody>
              {reports.map((rep) => (
                <TableRow key={rep.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-ink">
                        {rep.report_type}
                      </span>
                      <StatusBadge status={rep.status} />
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-ink-3">
                    {new Date(rep.created_at).toLocaleDateString()} {new Date(rep.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-ink-3">
                    {rep.generation_duration_ms ? `${rep.generation_duration_ms}ms` : "-"}
                  </TableCell>
                  <TableCell>
                    {rep.pdf_sha256 ? (
                      <CopyableValue value={rep.pdf_sha256} truncate label="PDF Digest" />
                    ) : rep.html_sha256 ? (
                      <CopyableValue value={rep.html_sha256} truncate label="HTML Digest" />
                    ) : (
                      "-"
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <ButtonLink
                        href={api.reports.getDownloadUrl(analysisId, rep.id, "pdf")}
                        download={`TunnelTrace_Report_${rep.report_type.toLowerCase()}_${rep.id.slice(0, 8)}.pdf`}
                        variant="primary"
                        size="sm"
                        title="Download native PDF file"
                      >
                        <Download className="w-3 h-3" />
                        <span>PDF</span>
                      </ButtonLink>

                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => {
                          const url = api.reports.getDownloadUrl(analysisId, rep.id, "html");
                          const win = window.open(url, "_blank");
                          if (win) {
                            win.onload = () => { win.print(); };
                          }
                        }}
                        title="Open printable HTML template"
                      >
                        <Printer className="w-3 h-3" />
                        <span>Print</span>
                      </Button>

                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => handlePreviewHtml(rep.id)}
                        title="Preview HTML in browser"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Preview</span>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState
            icon={<FileText className="w-5 h-5" />}
            title="No report artifacts generated yet"
            description="Generate an Executive or Technical PDF above to create a sealed report for this investigation."
            action={
              <Button variant="primary" size="sm" onClick={() => generateMutation.mutate("EXECUTIVE")}>
                <Printer className="w-3.5 h-3.5" />
                <span>Generate Executive PDF</span>
              </Button>
            }
          />
        )}
      </Section>

      {/* HTML Sandboxed Preview Modal */}
      {previewReportId && (
        <Card
          title="Sandboxed Report Preview"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  const iframe = document.querySelector('iframe[title="Report HTML Preview"]') as HTMLIFrameElement;
                  if (iframe && iframe.contentWindow) {
                    iframe.contentWindow.focus();
                    iframe.contentWindow.print();
                  } else {
                    window.print();
                  }
                }}
                title="Print report or save as PDF using browser print engine"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print / Save as PDF</span>
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setPreviewReportId(null);
                  setReportHtml(null);
                }}
              >
                <X className="w-3.5 h-3.5" />
                <span>Close</span>
              </Button>
            </div>
          }
        >
          {isPreviewLoading ? (
            <div role="status" aria-live="polite">
              <EmptyState compact title="Retrieving sanitized HTML document from storage..." />
            </div>
          ) : reportHtml ? (
            <div className="border border-line bg-ground">
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
