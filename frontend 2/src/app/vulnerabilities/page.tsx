"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  VulnerabilityReportPreviewResponseDTO,
  VulnerabilityFindingDTO,
} from "@/lib/api/types";
import { Section } from "@/components/ui/section";
import { Subsection } from "@/components/ui/section";
import { Tabs } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/ui/badge";
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
import { EmptyState } from "@/components/ui/empty-state";
import { Button, ButtonLink } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Stat, StatGrid } from "@/components/ui/stat";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  CheckCircle2,
  XCircle,
  Eye,
  Server,
  Layers,
  ChevronDown,
  ChevronRight,
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
  const [isBoundaryOpen, setIsBoundaryOpen] = useState(false);

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
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vulnerability-reports"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerability-findings"] });
      setSelectedFile(null);
      setPreviewData(null);
      setActiveTab("reports");
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

  const assetLinkClass = (state: string) => {
    if (state === "MAPPED_EXACT_IP") return "bg-positive-bg text-positive border-positive-border";
    if (state === "OUT_OF_SCOPE") return "bg-critical-bg text-critical border-critical-border";
    return "bg-info-bg text-info border-info-border";
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 border-b border-line pb-4">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-accent" />
            <span>External Vulnerability Assessment</span>
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-mono px-2 py-0.5 border border-line bg-panel-2 text-ink-2 uppercase tracking-wide">
              Greenbone / OpenVAS XML
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 border border-positive-border bg-positive-bg text-positive uppercase tracking-wide">
              Supplemental Evidence
            </span>
          </div>
          <p className="text-[13px] text-ink-2">
            Import and correlate external vulnerability scans as supplemental evidence. Does not alter deterministic packet-verified policy scores.
          </p>
        </div>

        {/* Cross-Flow Navigation */}
        <ButtonLink href="/discovery" variant="secondary" size="sm">
          <Server className="h-3.5 w-3.5 text-positive" />
          <span>Nmap Discovery</span>
        </ButtonLink>
      </div>

      {/* Epistemic Boundary Notice (expandable) */}
      <div className="border border-line bg-panel">
        <button
          type="button"
          onClick={() => setIsBoundaryOpen((prev) => !prev)}
          aria-expanded={isBoundaryOpen}
          className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left"
        >
          <span className="flex items-center gap-2 text-sm font-semibold text-ink">
            <AlertTriangle className="h-4 w-4 text-medium shrink-0" />
            <span>Epistemic Boundary: Scanner Assertions Are Supplemental Evidence, Not Ground Truth</span>
          </span>
          {isBoundaryOpen ? (
            <ChevronDown className="w-4 h-4 text-ink-3 shrink-0" />
          ) : (
            <ChevronRight className="w-4 h-4 text-ink-3 shrink-0" />
          )}
        </button>
        {isBoundaryOpen && (
          <div className="px-4 pb-4">
            <div className="border border-medium-border bg-medium-bg p-3 text-[13px] leading-relaxed text-ink-2">
              Greenbone/OpenVAS results represent scanner-reported claims (typically based on unauthenticated banners or remote heuristics).
              TunnelTrace strictly preserves uncertainty: unauthenticated banner detections are marked{" "}
              <strong className="text-medium">POTENTIAL</strong> or <strong className="text-ink">UNKNOWN</strong>.
              They are never upgraded to confirmed vulnerabilities, and never silently deduct from your deterministic Security Score.
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <Tabs
        active={activeTab}
        onChange={(id) => setActiveTab(id as typeof activeTab)}
        items={[
          { id: "import", label: "Import & Preview" },
          { id: "reports", label: "Imported Reports", count: reportsData?.total || 0 },
          { id: "findings", label: "Findings Explorer" },
        ]}
      />

      {/* TAB 1: IMPORT & PREVIEW */}
      {activeTab === "import" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Upload & Attestation Form */}
          <div className="space-y-4">
            <Section title="Upload Greenbone XML Report">
              <div className="space-y-4">
                {formError && (
                  <div role="alert" className="border border-critical-border bg-critical-bg text-critical text-xs flex items-center gap-2 p-3">
                    <XCircle className="h-4 w-4 shrink-0" />
                    <span>{formError}</span>
                  </div>
                )}

                {/* File Select */}
                <Field label="Report Artifact (.xml)" required>
                  <Input
                    type="file"
                    accept=".xml"
                    onChange={handleFileChange}
                  />
                  <p className="text-xs text-ink-3">
                    Accepts Greenbone/OpenVAS XML report export or GMP &lt;get_reports_response&gt; envelope.
                  </p>
                </Field>
              </div>
            </Section>

            <Section title="Operator Authorization Attestation">
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Operator ID">
                    <Input
                      type="text"
                      value={operatorId}
                      onChange={(e) => setOperatorId(e.target.value)}
                    />
                  </Field>
                  <Field label="Auth Reference">
                    <Input
                      type="text"
                      value={authRef}
                      onChange={(e) => setAuthRef(e.target.value)}
                    />
                  </Field>
                </div>

                <Field label="Authorized Targets / Boundary" hint="Candidate mapping checks report host IPs against this boundary.">
                  <Input
                    type="text"
                    value={authorizedTargetsText}
                    onChange={(e) => setAuthorizedTargetsText(e.target.value)}
                    placeholder="198.51.100.0/24, 10.0.0.1"
                    mono
                  />
                </Field>

                <Field label="Engagement Scope Title">
                  <Input
                    type="text"
                    value={engagementScope}
                    onChange={(e) => setEngagementScope(e.target.value)}
                  />
                </Field>

                <Field label="Written Attestation">
                  <Textarea
                    rows={2}
                    value={authAttestation}
                    onChange={(e) => setAuthAttestation(e.target.value)}
                  />
                </Field>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={hasConfirmedAttestation}
                    onChange={(e) => setHasConfirmedAttestation(e.target.checked)}
                    className="accent-accent"
                  />
                  <span className="text-[13px] text-ink-2">
                    I confirm written authorization exists for importing this assessment evidence.
                  </span>
                </label>
              </div>
            </Section>

            {/* Action Buttons */}
            <div className="flex items-center gap-3">
              <Button
                variant="secondary"
                onClick={() => previewMutation.mutate()}
                disabled={!selectedFile || previewMutation.isPending}
                className="flex-1"
              >
                <Eye className="h-3.5 w-3.5" />
                <span>{previewMutation.isPending ? "Parsing XML…" : "Preflight Preview"}</span>
              </Button>

              <Button
                variant="primary"
                onClick={() => importMutation.mutate()}
                disabled={!selectedFile || !hasConfirmedAttestation || importMutation.isPending}
                className="flex-1"
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>{importMutation.isPending ? "Importing…" : "Confirm & Import"}</span>
              </Button>
            </div>
          </div>

          {/* Preflight Preview Output */}
          <div className="flex flex-col gap-3">
          {previewData ? (
            <Section title={`Preflight Preview: ${previewData.task_name || previewData.report_id}`}>
              <div className="space-y-4 font-mono">
                <div className="text-xs text-ink-3">
                  SHA-256: {previewData.raw_sha256.substring(0, 16)}…
                </div>

                {/* Metrics Grid */}
                <StatGrid className="sm:grid-cols-2 lg:grid-cols-4">
                  <Stat label="Findings" value={previewData.total_findings_count} />
                  <Stat label="Hosts" value={previewData.unique_hosts_count} />
                  <Stat label="Exact Match" value={previewData.host_mapping_summary.mapped_exact_ip} tone="positive" />
                  <Stat label="Feed State" value={previewData.feed_status} mono={false} />
                </StatGrid>

                {/* Asset Mapping Breakdown */}
                <Subsection title="Host Mapping Verification">
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {previewData.host_mapping_details.map((h, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between gap-2 p-2 border border-line bg-panel text-xs"
                      >
                        <span className="font-semibold text-ink">{h.host_ip}</span>
                        <span className={`px-2 py-0.5 text-[11px] font-semibold border ${assetLinkClass(h.asset_link_state)}`}>
                          {h.asset_link_state}
                        </span>
                      </div>
                    ))}
                  </div>
                </Subsection>
              </div>
            </Section>
          ) : (
            <div className="flex min-h-[34rem] flex-col items-center justify-center border-y border-line px-5 py-10 text-center">
              <div className="grid h-14 w-14 place-items-center border-2 border-ink bg-panel-2"><FileText className="h-6 w-6 text-brand" /></div>
              <span className="micro-label mt-5 text-ink-3">Preflight · step 1 of 2</span>
              <h2 className="mt-2 max-w-[16ch] font-sans text-3xl font-extrabold tracking-tight">Review before import.</h2>
              <p className="mt-3 max-w-[46ch] text-sm leading-6 text-ink-2">Choose a Greenbone XML report, then run Preflight Preview to inspect its metadata, host mapping, and target coordinates before ingestion.</p>
              <div className="mt-7 grid w-full max-w-xl gap-2 text-left sm:grid-cols-3">
                <div className="border border-line bg-panel p-3"><span className="font-mono text-xs text-brand">01</span><p className="mt-2 text-sm font-bold">Select report</p><p className="mt-1 text-xs text-ink-3">XML artifact</p></div>
                <div className="border border-line bg-panel p-3"><span className="font-mono text-xs text-brand">02</span><p className="mt-2 text-sm font-bold">Inspect scope</p><p className="mt-1 text-xs text-ink-3">Hosts and mapping</p></div>
                <div className="border border-line bg-panel p-3"><span className="font-mono text-xs text-brand">03</span><p className="mt-2 text-sm font-bold">Confirm import</p><p className="mt-1 text-xs text-ink-3">Operator attestation</p></div>
              </div>
              <Button variant="primary" size="md" className="mt-5" onClick={() => setActiveTab("reports")}><Layers className="h-4 w-4" />View imported reports</Button>
            </div>
          )}
          </div>
        </div>
      )}

      {/* TAB 2: REPORTS LIST */}
      {activeTab === "reports" && (
        <Section title="Imported Greenbone Report Artifacts">
          {isReportsLoading ? (
            <EmptyState compact title="Loading reports…" />
          ) : reportsData?.reports && reportsData.reports.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Task Name / ID</TableHead>
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
                      <div className="font-semibold text-xs text-ink">
                        {r.task_name || r.report_source_id}
                      </div>
                      <div className="text-[11px] text-ink-3">
                        {r.report_source_id}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs truncate max-w-[180px]">
                        {r.engagement_scope}
                      </div>
                      <div className="text-[11px] text-ink-3">
                        Op: {r.operator_id}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs">
                        {r.scan_started_at ? new Date(r.scan_started_at).toLocaleDateString() : "Unknown"}
                      </div>
                      <div className="text-[11px] text-ink-3">
                        Feed: {r.feed_status}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="font-semibold text-accent-ink">
                        {r.results_count} findings
                      </span>
                      <span className="text-ink-3"> on {r.hosts_count} hosts</span>
                    </TableCell>
                    <TableCell>
                      <CopyableValue value={r.raw_artifact_sha256} truncate />
                    </TableCell>
                    <TableCell>
                      <span className="text-[11px] px-1.5 py-0.5 border border-line uppercase text-ink-2">
                        {r.status}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <button
                        onClick={() => {
                          setSelectedReportId(r.id);
                          setActiveTab("findings");
                        }}
                        className="px-2.5 py-1 text-xs font-semibold text-accent-ink hover:underline"
                      >
                        View Findings
                      </button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState
              icon={<FileText />}
              title="No Greenbone reports imported yet"
              description="Go to the Import & Preview tab to upload an XML report."
              action={
                <Button variant="secondary" size="sm" onClick={() => setActiveTab("import")}>
                  Go to Import & Preview
                </Button>
              }
            />
          )}
        </Section>
      )}

      {/* TAB 3: FINDINGS EXPLORER */}
      {activeTab === "findings" && (
        <Section title="Vulnerability Findings Explorer">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-line pb-2">
              <span className="text-xs text-ink-3">
                {selectedReportId
                  ? `Filtering findings for report ID: ${selectedReportId}`
                  : "Displaying findings across all imported reports."}
              </span>
              {selectedReportId && (
                <button
                  onClick={() => setSelectedReportId(null)}
                  className="text-xs text-accent-ink hover:underline"
                >
                  Clear Filter (Show All)
                </button>
              )}
            </div>

            {isFindingsLoading ? (
              <EmptyState compact title="Loading findings…" />
            ) : findingsData?.findings && findingsData.findings.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Host & Port</TableHead>
                    <TableHead>Vulnerability (NVT)</TableHead>
                    <TableHead>Severity / QoD</TableHead>
                    <TableHead>CVEs</TableHead>
                    <TableHead>Asset Link</TableHead>
                    <TableHead>Correlation</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingsData.findings.map((f) => (
                    <TableRow
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                    >
                      <TableCell>
                        <div className="font-semibold text-xs text-ink">{f.host_ip}</div>
                        <div className="text-[11px] text-ink-3">
                          {f.port ? `${f.port}/${f.protocol || "any"}` : "General"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium text-xs truncate max-w-[260px]">
                          {f.nvt_name}
                        </div>
                        <div className="text-[11px] text-ink-3">
                          OID: {f.nvt_oid}
                        </div>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={f.source_severity} />
                        {f.qod_value && (
                          <span className="text-[11px] text-ink-3 ml-1">
                            ({f.qod_value}%)
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1 max-w-[160px]">
                          {f.reported_cves && f.reported_cves.length > 0 ? (
                            f.reported_cves.slice(0, 2).map((cve, i) => (
                              <span
                                key={i}
                                className="text-[11px] px-1 border border-line bg-panel-2 text-ink-2"
                              >
                                {cve}
                              </span>
                            ))
                          ) : (
                            <span className="text-ink-3">—</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-[11px] px-1.5 py-0.5 border border-line uppercase text-ink-2">
                          {f.asset_link_state}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[11px] px-1.5 py-0.5 border border-medium-border text-medium uppercase font-semibold">
                          {f.correlation_status}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedFinding(f);
                          }}
                          className="px-2 py-1 text-xs text-accent-ink hover:underline font-semibold"
                        >
                          Inspect
                        </button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                icon={<ShieldAlert />}
                title="No findings found for the selected view"
                description="Import a Greenbone report or clear the report filter to see all findings."
                action={
                  selectedReportId ? (
                    <Button variant="secondary" size="sm" onClick={() => setSelectedReportId(null)}>
                      Clear Filter (Show All)
                    </Button>
                  ) : undefined
                }
              />
            )}
          </div>
        </Section>
      )}

      {/* Finding Detail Inspector Drawer */}
      {selectedFinding && (
        <InspectorDrawer
          isOpen={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          title="Vulnerability Finding Evidence"
        >
          <div className="p-2 space-y-5 font-mono text-xs text-ink-2">
            <div className="space-y-1">
              <span className="text-[11px] text-ink-3 uppercase font-semibold">
                Scanner Assertion
              </span>
              <h2 className="text-section font-semibold text-ink">
                {selectedFinding.nvt_name}
              </h2>
              <div className="text-[11px] text-ink-3">OID: {selectedFinding.nvt_oid}</div>
            </div>

            <div className="grid grid-cols-3 gap-2 border border-line bg-panel-2 p-3 text-center">
              <div>
                <div className="text-[11px] text-ink-3 uppercase">Severity</div>
                <div className="mt-0.5">
                  <SeverityBadge severity={selectedFinding.source_severity} />
                </div>
              </div>
              <div>
                <div className="text-[11px] text-ink-3 uppercase">CVSS Base</div>
                <div className="font-semibold text-ink mt-0.5">
                  {selectedFinding.cvss_base_score ?? "None"}
                </div>
              </div>
              <div>
                <div className="text-[11px] text-ink-3 uppercase">QoD</div>
                <div className="font-semibold text-medium mt-0.5">
                  {selectedFinding.qod_value ? `${selectedFinding.qod_value}%` : "Unknown"}
                </div>
              </div>
            </div>

            <div className="border border-line bg-panel-2 p-3 space-y-1.5">
              <div>
                <span className="text-ink-3">Host IP:</span>{" "}
                <span className="font-semibold text-ink">{selectedFinding.host_ip}</span>
              </div>
              <div>
                <span className="text-ink-3">Port / Protocol:</span>{" "}
                <span>{selectedFinding.port ? `${selectedFinding.port}/${selectedFinding.protocol}` : "General Host"}</span>
              </div>
              <div>
                <span className="text-ink-3">Asset Link State:</span>{" "}
                <span className="font-semibold text-ink">{selectedFinding.asset_link_state}</span>
              </div>
              <div className="text-[11px] text-ink-3 italic">
                {selectedFinding.asset_link_rationale}
              </div>
            </div>

            {selectedFinding.description && (
              <div className="space-y-1">
                <span className="font-semibold text-ink uppercase text-[11px]">
                  Description
                </span>
                <p className="border border-line bg-panel-2 p-3 text-[13px] leading-relaxed">
                  {selectedFinding.description}
                </p>
              </div>
            )}

            {selectedFinding.solution && (
              <div className="space-y-1">
                <span className="font-semibold text-ink uppercase text-[11px]">
                  Scanner Solution Guidance
                </span>
                <p className="border border-line bg-panel-2 p-3 text-[13px] leading-relaxed">
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
