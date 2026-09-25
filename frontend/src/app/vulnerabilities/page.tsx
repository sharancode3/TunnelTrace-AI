"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  VulnerabilityReportPreviewResponseDTO,
  VulnerabilityFindingDTO,
} from "@/lib/api/types";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  UploadCloud,
  CheckCircle2,
  XCircle,
  Eye,
  Server,
  Layers,
  Search,
} from "lucide-react";

export default function VulnerabilityReportsPage() {
  const queryClient = useQueryClient();

  // Tab State
  const [activeTab, setActiveTab] = useState<"import" | "reports" | "findings">("import");

  // Form State for Import
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [operatorId, setOperatorId] = useState("operator-admin");
  const [authRef, setAuthRef] = useState("CHG-2026-VULN-01");
  const [engagementScope, setEngagementScope] = useState("198.51.100.0/24, 10.0.0.0/16");
  const [authAttestation, setAuthAttestation] = useState(
    "I attest that this Greenbone/OpenVAS vulnerability report is authorized for import into TunnelTrace AI as supplemental evidence."
  );
  const [hasConfirmedAttestation, setHasConfirmedAttestation] = useState(false);
  const [authorizedTargetsText, setAuthorizedTargetsText] = useState("198.51.100.0/24");
  const [formError, setFormError] = useState<string | null>(null);
  const [previewData, setPreviewData] = useState<VulnerabilityReportPreviewResponseDTO | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFindingDTO | null>(null);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);

  // Queries
  const { data: reportsData, isLoading: isReportsLoading } = useQuery({
    queryKey: ["vulnerability-reports"],
    queryFn: () => api.vulnerabilities.listReports(0, 50),
  });

  const { data: findingsData, isLoading: isFindingsLoading } = useQuery({
    queryKey: ["vulnerability-findings", selectedReportId],
    queryFn: () => api.vulnerabilities.listFindings(selectedReportId || undefined, { limit: 100 }),
  });

  // Mutations
  const previewMutation = useMutation({
    mutationFn: async () => {
      if (!selectedFile) throw new Error("Please select an XML report file.");
      return api.vulnerabilities.previewReport(selectedFile, authorizedTargetsText);
    },
    onSuccess: (data) => {
      setPreviewData(data);
      setFormError(null);
    },
    onError: (err: Error) => {
      setFormError(err.message || "Failed to preview report.");
      setPreviewData(null);
    },
  });

  const importMutation = useMutation({
    mutationFn: async () => {
      if (!selectedFile) throw new Error("Please select an XML report file.");
      if (!hasConfirmedAttestation) {
        throw new Error("Operator attestation confirmation is required.");
      }
      return api.vulnerabilities.importReport(selectedFile, {
        operator_id: operatorId,
        authorization_reference: authRef,
        operator_attestation: authAttestation,
        engagement_scope: engagementScope,
        authorized_targets: authorizedTargetsText,
      });
    },
    onSuccess: (report) => {
      queryClient.invalidateQueries({ queryKey: ["vulnerability-reports"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerability-findings"] });
      setSelectedReportId(report.id);
      setActiveTab("findings");
      setPreviewData(null);
      setSelectedFile(null);
      setFormError(null);
    },
    onError: (err: Error) => {
      setFormError(err.message || "Failed to import report.");
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setPreviewData(null);
      setFormError(null);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* Top Header & Context Badges */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <ShieldAlert className="h-7 w-7 text-indigo-400" />
              External Vulnerability Assessment
            </h1>
            <span className="text-xs px-2.5 py-0.5 rounded-full font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Greenbone / OpenVAS XML
            </span>
            <span className="text-xs px-2.5 py-0.5 rounded-full font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Supplemental Evidence
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Import and cautiously correlate external scanner assertions. Zero impact on deterministic Policy-as-Code scores.
          </p>
        </div>

        {/* Cross-Flow Navigation */}
        <div className="flex items-center gap-2">
          <Link
            href="/discovery"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
          >
            <Server className="h-4 w-4 text-emerald-400" />
            Nmap Asset Discovery
          </Link>
          <div className="h-4 w-[1px] bg-slate-800 mx-1" />
          <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-1">
            <button
              onClick={() => setActiveTab("import")}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                activeTab === "import" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Import & Preview
            </button>
            <button
              onClick={() => setActiveTab("reports")}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                activeTab === "reports" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Reports ({reportsData?.total || 0})
            </button>
            <button
              onClick={() => setActiveTab("findings")}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                activeTab === "findings" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Findings Explorer
            </button>
          </div>
        </div>
      </div>

      {/* Disclaimers & Epistemic Notice */}
      <Card className="p-4 bg-slate-900/60 border border-amber-500/20 text-slate-300">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5 shrink-0" />
          <div className="text-xs space-y-1">
            <p className="font-semibold text-amber-300">
              Epistemic Boundary: Scanner Assertions Are Supplemental Evidence, Not Truth
            </p>
            <p className="text-slate-400">
              Greenbone/OpenVAS results represent scanner-reported claims (typically based on unauthenticated banners or remote heuristics).
              TunnelTrace strictly preserves uncertainty: unauthenticated banner detections are marked{" "}
              <strong className="text-amber-300">POTENTIAL</strong> or <strong className="text-slate-300">UNKNOWN</strong>.
              They are never upgraded to confirmed vulnerabilities, and never silently deduct from your deterministic Security Score.
            </p>
          </div>
        </div>
      </Card>

      {/* TAB 1: IMPORT & PREVIEW */}
      {activeTab === "import" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Upload & Attestation Form */}
          <div className="lg:col-span-6 space-y-4">
            <Card className="p-6 bg-slate-900 border border-slate-800 space-y-5">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <UploadCloud className="h-5 w-5 text-indigo-400" />
                Upload Greenbone XML Report
              </h2>

              {formError && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs flex items-center gap-2">
                  <XCircle className="h-4 w-4 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              {/* File Select */}
              <div className="space-y-2">
                <label className="text-xs font-semibold text-slate-300">Report Artifact (.xml)</label>
                <input
                  type="file"
                  accept=".xml"
                  onChange={handleFileChange}
                  className="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-indigo-600 file:text-white hover:file:bg-indigo-500 cursor-pointer bg-slate-950 border border-slate-800 rounded-lg p-2"
                />
                <p className="text-[11px] text-slate-500">
                  Accepts Greenbone/OpenVAS XML report export or GMP &lt;get_reports_response&gt; envelope.
                </p>
              </div>

              {/* Operator Attestation Card */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    Operator Authorization Attestation
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] font-medium text-slate-400">Operator ID</label>
                    <input
                      type="text"
                      value={operatorId}
                      onChange={(e) => setOperatorId(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-white"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-medium text-slate-400">Authorization Reference</label>
                    <input
                      type="text"
                      value={authRef}
                      onChange={(e) => setAuthRef(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-white"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] font-medium text-slate-400">Authorized Target CIDRs / Boundary</label>
                  <input
                    type="text"
                    value={authorizedTargetsText}
                    onChange={(e) => setAuthorizedTargetsText(e.target.value)}
                    placeholder="198.51.100.0/24, 10.0.0.1"
                    className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-white font-mono"
                  />
                  <p className="text-[10px] text-slate-500">
                    Candidate mapping checks report host IPs against this boundary.
                  </p>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] font-medium text-slate-400">Engagement Scope Title</label>
                  <input
                    type="text"
                    value={engagementScope}
                    onChange={(e) => setEngagementScope(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-white"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] font-medium text-slate-400">Written Attestation</label>
                  <textarea
                    rows={2}
                    value={authAttestation}
                    onChange={(e) => setAuthAttestation(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-white"
                  />
                </div>

                <label className="flex items-center gap-2 cursor-pointer pt-1">
                  <input
                    type="checkbox"
                    checked={hasConfirmedAttestation}
                    onChange={(e) => setHasConfirmedAttestation(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-indigo-600 focus:ring-indigo-500"
                  />
                  <span className="text-xs text-slate-300">
                    I confirm written authorization exists for importing this assessment evidence.
                  </span>
                </label>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => previewMutation.mutate()}
                  disabled={!selectedFile || previewMutation.isPending}
                  className="flex-1 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors border border-slate-700"
                >
                  <Eye className="h-4 w-4 text-indigo-400" />
                  {previewMutation.isPending ? "Parsing XML..." : "Preflight Preview"}
                </button>

                <button
                  type="button"
                  onClick={() => importMutation.mutate()}
                  disabled={
                    !selectedFile ||
                    !hasConfirmedAttestation ||
                    importMutation.isPending
                  }
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-lg shadow-indigo-600/20"
                >
                  <CheckCircle2 className="h-4 w-4" />
                  {importMutation.isPending ? "Importing..." : "Confirm & Import Report"}
                </button>
              </div>
            </Card>
          </div>

          {/* Preflight Preview Output */}
          <div className="lg:col-span-6 space-y-4">
            {previewData ? (
              <Card className="p-6 bg-slate-900 border border-indigo-500/30 space-y-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <FileText className="h-4 w-4 text-indigo-400" />
                    Preflight Preview: {previewData.task_name || previewData.report_id}
                  </h3>
                  <span className="text-[11px] font-mono text-slate-400">
                    SHA: {previewData.raw_sha256.substring(0, 12)}...
                  </span>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">Findings</div>
                    <div className="text-base font-bold text-white mt-0.5">
                      {previewData.total_findings_count}
                    </div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">Hosts</div>
                    <div className="text-base font-bold text-white mt-0.5">
                      {previewData.unique_hosts_count}
                    </div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">Exact IP Match</div>
                    <div className="text-base font-bold text-emerald-400 mt-0.5">
                      {previewData.host_mapping_summary.mapped_exact_ip}
                    </div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">Feed Status</div>
                    <div className="text-xs font-semibold text-amber-400 mt-1">
                      {previewData.feed_status}
                    </div>
                  </div>
                </div>

                {/* Scope & Mapping Breakdown */}
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                    <Layers className="h-3.5 w-3.5 text-indigo-400" />
                    Asset Mapping Verification
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                    {previewData.host_mapping_details.map((h, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 text-xs"
                      >
                        <span className="font-mono text-slate-200">{h.host_ip}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            h.asset_link_state === "MAPPED_EXACT_IP"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : h.asset_link_state === "OUT_OF_SCOPE"
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                              : "bg-slate-800 text-slate-400 border border-slate-700"
                          }`}
                        >
                          {h.asset_link_state}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Sample Findings Preview */}
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-300">Sample Normalized Findings</div>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {previewData.findings_sample.map((f, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-slate-200 truncate max-w-[280px]">
                            {f.nvt_name}
                          </span>
                          <span className="text-[10px] font-semibold text-indigo-400">
                            {f.source_severity} (QoD: {f.qod_value ?? "?"}%)
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
                          <span>{f.host_ip}:{f.port ?? "all"}</span>
                          <span>•</span>
                          <span className="text-amber-400">{f.correlation_status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            ) : (
              <Card className="p-12 bg-slate-900 border border-slate-800 text-center flex flex-col items-center justify-center space-y-3">
                <FileText className="h-10 w-10 text-slate-600" />
                <h3 className="text-sm font-semibold text-slate-400">No Preflight Preview Active</h3>
                <p className="text-xs text-slate-500 max-w-sm">
                  Select a Greenbone XML report file and click <strong>Preflight Preview</strong> to inspect metadata, feed state, and host mapping before importing.
                </p>
              </Card>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: REPORTS LIST */}
      {activeTab === "reports" && (
        <Card className="p-6 bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <FileText className="h-5 w-5 text-indigo-400" />
              Imported Greenbone Report Artifacts
            </h2>
            <span className="text-xs text-slate-400">
              Total Reports: {reportsData?.total || 0}
            </span>
          </div>

          {isReportsLoading ? (
            <div className="p-8 text-center text-xs text-slate-500">Loading reports...</div>
          ) : reportsData?.reports && reportsData.reports.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Task Name / Source ID</TableHead>
                  <TableHead>Scope & Attestation</TableHead>
                  <TableHead>Scan Window</TableHead>
                  <TableHead>Findings / Hosts</TableHead>
                  <TableHead>Artifact SHA-256</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reportsData.reports.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <div className="font-medium text-slate-200 text-xs">
                        {r.task_name || r.report_source_id}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        {r.report_source_id}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs text-slate-300 font-mono truncate max-w-[180px]">
                        {r.engagement_scope}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Op: {r.operator_id} (Local Attestation)
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs text-slate-300">
                        {r.scan_started_at ? new Date(r.scan_started_at).toLocaleString() : "Unknown"}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Feed: {r.feed_status}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs font-semibold text-indigo-400">
                        {r.results_count} findings
                      </span>
                      <span className="text-slate-500 text-xs"> on {r.hosts_count} hosts</span>
                    </TableCell>
                    <TableCell>
                      <CopyableValue value={r.raw_artifact_sha256} truncate />
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          r.status === "COMPLETED"
                            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            : r.status === "COMPLETED_WITH_WARNINGS"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                            : "bg-slate-800 text-slate-400 border border-slate-700"
                        }`}
                      >
                        {r.status}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <button
                        onClick={() => {
                          setSelectedReportId(r.id);
                          setActiveTab("findings");
                        }}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-indigo-400 hover:text-indigo-300 rounded text-xs font-medium transition-colors"
                      >
                        View Findings
                      </button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500">
              No Greenbone reports imported yet. Go to the <strong>Import & Preview</strong> tab to upload an XML report.
            </div>
          )}
        </Card>
      )}

      {/* TAB 3: FINDINGS EXPLORER */}
      {activeTab === "findings" && (
        <Card className="p-6 bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Search className="h-5 w-5 text-indigo-400" />
                Vulnerability Findings Explorer
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                {selectedReportId
                  ? `Filtering findings for report ID: ${selectedReportId}`
                  : "Displaying findings across all imported reports."}
              </p>
            </div>
            {selectedReportId && (
              <button
                onClick={() => setSelectedReportId(null)}
                className="text-xs text-slate-400 hover:text-white underline"
              >
                Clear Report Filter (Show All)
              </button>
            )}
          </div>

          {isFindingsLoading ? (
            <div className="p-8 text-center text-xs text-slate-500">Loading findings...</div>
          ) : findingsData?.findings && findingsData.findings.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host & Port</TableHead>
                  <TableHead>Vulnerability (NVT)</TableHead>
                  <TableHead>Severity / QoD</TableHead>
                  <TableHead>CVEs Asserted</TableHead>
                  <TableHead>Asset Link State</TableHead>
                  <TableHead>Correlation Status</TableHead>
                  <TableHead className="text-right">Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findingsData.findings.map((f) => (
                  <TableRow
                    key={f.id}
                    className="cursor-pointer hover:bg-slate-800/40"
                    onClick={() => setSelectedFinding(f)}
                  >
                    <TableCell>
                      <div className="font-mono text-xs text-slate-200">{f.host_ip}</div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        {f.port ? `${f.port}/${f.protocol || "any"}` : "General Host"}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium text-xs text-slate-200 line-clamp-1 max-w-[260px]">
                        {f.nvt_name}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        OID: {f.nvt_oid}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            f.source_severity === "Critical" || f.source_severity === "High"
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                              : f.source_severity === "Medium"
                              ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                              : "bg-slate-800 text-slate-400 border border-slate-700"
                          }`}
                        >
                          {f.source_severity}
                        </span>
                        {f.qod_value && (
                          <span className="text-[10px] text-slate-400">
                            (QoD {f.qod_value}%)
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1 max-w-[180px]">
                        {f.reported_cves && f.reported_cves.length > 0 ? (
                          f.reported_cves.slice(0, 2).map((cve, i) => (
                            <span
                              key={i}
                              className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono"
                            >
                              {cve}
                            </span>
                          ))
                        ) : (
                          <span className="text-[11px] text-slate-500">—</span>
                        )}
                        {f.reported_cves && f.reported_cves.length > 2 && (
                          <span className="text-[10px] text-slate-500">
                            +{f.reported_cves.length - 2}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          f.asset_link_state === "MAPPED_EXACT_IP"
                            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            : f.asset_link_state === "OUT_OF_SCOPE"
                            ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                            : "bg-slate-800 text-slate-400 border border-slate-700"
                        }`}
                      >
                        {f.asset_link_state}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          f.correlation_status === "POTENTIAL"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                            : f.correlation_status === "UNKNOWN"
                            ? "bg-slate-800 text-slate-400 border border-slate-700"
                            : "bg-slate-800 text-slate-400 border border-slate-700"
                        }`}
                      >
                        {f.correlation_status}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-indigo-400 rounded text-xs"
                      >
                        Inspect
                      </button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500">
              No findings found. Try selecting another report or importing an XML report.
            </div>
          )}
        </Card>
      )}

      {/* FINDING DETAIL INSPECTOR DRAWER */}
      {selectedFinding && (
        <InspectorDrawer
          isOpen={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          title="Finding Evidence Detail"
        >
          <div className="p-6 space-y-6 text-slate-300">
            {/* Finding Name & NVT */}
            <div className="space-y-1">
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
                Scanner-Reported Finding
              </span>
              <h2 className="text-lg font-bold text-white">{selectedFinding.nvt_name}</h2>
              <div className="text-xs text-slate-400 font-mono">OID: {selectedFinding.nvt_oid}</div>
            </div>

            {/* Severity & QoD Grid */}
            <div className="grid grid-cols-3 gap-2 bg-slate-900 p-3 rounded-lg border border-slate-800 text-center">
              <div>
                <div className="text-[10px] uppercase text-slate-500">Reported Severity</div>
                <div className="text-xs font-bold text-rose-400 mt-0.5">
                  {selectedFinding.source_severity}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase text-slate-500">CVSS Base</div>
                <div className="text-xs font-bold text-white mt-0.5">
                  {selectedFinding.cvss_base_score ?? "None"}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase text-slate-500">QoD (Confidence)</div>
                <div className="text-xs font-bold text-amber-400 mt-0.5">
                  {selectedFinding.qod_value ? `${selectedFinding.qod_value}%` : "Unknown"}
                </div>
              </div>
            </div>

            {/* Target Coordinates */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-200">Target Coordinates</h3>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 space-y-1 text-xs">
                <div>
                  <span className="text-slate-500">Host IP:</span>{" "}
                  <span className="font-mono text-slate-200">{selectedFinding.host_ip}</span>
                </div>
                <div>
                  <span className="text-slate-500">Port / Protocol:</span>{" "}
                  <span className="font-mono text-slate-200">
                    {selectedFinding.port ? `${selectedFinding.port}/${selectedFinding.protocol}` : "General Host"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Asset Link State:</span>{" "}
                  <span className="text-indigo-400 font-semibold">{selectedFinding.asset_link_state}</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1 italic">
                  {selectedFinding.asset_link_rationale}
                </div>
              </div>
            </div>

            {/* Product & Version Claims */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-200">Product / Version Assertion</h3>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 space-y-1 text-xs">
                <div>
                  <span className="text-slate-500">Asserted Product:</span>{" "}
                  <span className="font-mono text-slate-200">
                    {selectedFinding.source_product_claim || "Not specified in report"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Asserted Version:</span>{" "}
                  <span className="font-mono text-slate-200">
                    {selectedFinding.source_version_claim || "Not specified in report"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Correlation Status:</span>{" "}
                  <span className="text-amber-400 font-semibold">{selectedFinding.correlation_status}</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1 italic">
                  {selectedFinding.correlation_rationale}
                </div>
              </div>
            </div>

            {/* CVE References */}
            {selectedFinding.reported_cves && selectedFinding.reported_cves.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-slate-200">Reported CVE Identifiers</h3>
                <div className="flex flex-wrap gap-2">
                  {selectedFinding.reported_cves.map((cve, i) => (
                    <span
                      key={i}
                      className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Description & Solution */}
            {selectedFinding.description && (
              <div className="space-y-1">
                <h3 className="text-xs font-semibold text-slate-200">Description</h3>
                <p className="text-xs text-slate-400 leading-relaxed bg-slate-900 p-3 rounded-lg border border-slate-800">
                  {selectedFinding.description}
                </p>
              </div>
            )}

            {selectedFinding.solution && (
              <div className="space-y-1">
                <h3 className="text-xs font-semibold text-slate-200">Scanner Solution Guidance</h3>
                <p className="text-xs text-slate-400 leading-relaxed bg-slate-900 p-3 rounded-lg border border-slate-800">
                  {selectedFinding.solution}
                </p>
              </div>
            )}
          </div>
        </InspectorDrawer>
      )}
    </div>
  );
}
