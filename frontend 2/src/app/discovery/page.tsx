"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  DiscoveryJobCreateRequestDTO,
  DiscoveryJobDTO,
  DiscoveryStatusDTO,
} from "@/lib/api/types";
import { Section } from "@/components/ui/section";
import { StatusBadge } from "@/components/ui/badge";
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
import { Button, ButtonLink } from "@/components/ui/button";
import { Field, Input, Textarea, Select } from "@/components/ui/input";
import { Stat, StatGrid } from "@/components/ui/stat";
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  RotateCw,
  HelpCircle,
  Terminal,
  Ban,
  Layers,
} from "lucide-react";

export default function DiscoveryPage() {
  const queryClient = useQueryClient();

  // Form State
  const [jobName, setJobName] = useState("Authorized VPN Discovery");
  const [operatorId, setOperatorId] = useState("operator-admin");
  const [authRef, setAuthRef] = useState("CHG-2026-0924");
  const [authAttestation, setAuthAttestation] = useState(
    "I attest that written authorization has been granted for active IPsec discovery on these approved targets."
  );
  const [hasConfirmedAttestation, setHasConfirmedAttestation] = useState(false);
  const [profile, setProfile] = useState("IKE_SERVICE_DISCOVERY");
  const [targetsText, setTargetsText] = useState("127.0.0.1");
  const [exclusionsText, setExclusionsText] = useState("");
  const [portsText, setPortsText] = useState("");
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  // Queries
  const { data: statusData, isLoading: isStatusLoading } = useQuery<DiscoveryStatusDTO>({
    queryKey: ["discovery-status"],
    queryFn: () => api.discovery.getStatus(),
  });

  const { data: jobs, isLoading: isJobsLoading, refetch: refetchJobs } = useQuery<DiscoveryJobDTO[]>({
    queryKey: ["discovery-jobs"],
    queryFn: () => api.discovery.listJobs(),
  });

  const activeJob = jobs?.find((j) => j.id === (selectedJobId || jobs[0]?.id));

  // Mutations
  const createJobMutation = useMutation({
    mutationFn: (req: DiscoveryJobCreateRequestDTO) => api.discovery.createJob(req),
    onSuccess: (newJob) => {
      queryClient.invalidateQueries({ queryKey: ["discovery-jobs"] });
      setSelectedJobId(newJob.id);
      setShowConfirmModal(false);
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err.message || "Failed to submit discovery job.");
      setShowConfirmModal(false);
    },
  });

  const cancelJobMutation = useMutation({
    mutationFn: (jobId: string) => api.discovery.cancelJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["discovery-jobs"] });
    },
  });

  // Target Parsing Preview
  const parsedTargets = targetsText
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const parsedExclusions = exclusionsText
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const parsedPorts = portsText
    .split(/[\n,]+/)
    .map((p) => parseInt(p.trim(), 10))
    .filter((p) => !isNaN(p) && p >= 1 && p <= 65535);

  const handleOpenConfirmation = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (parsedTargets.length === 0) {
      setFormError("At least one target IP, CIDR, or hostname is required.");
      return;
    }

    if (statusData && parsedTargets.length > statusData.max_targets) {
      setFormError(
        `Target count (${parsedTargets.length}) exceeds hard limit of ${statusData.max_targets}.`
      );
      return;
    }

    if (!hasConfirmedAttestation || authAttestation.trim().length < 10) {
      setFormError("You must explicitly verify and attest authorization before scanning.");
      return;
    }

    setShowConfirmModal(true);
  };

  const handleExecuteScan = () => {
    createJobMutation.mutate({
      job_name: jobName,
      operator_id: operatorId,
      authorization_reference: authRef,
      authorization_attestation: authAttestation,
      profile: profile,
      requested_targets: parsedTargets,
      exclusions: parsedExclusions.length > 0 ? parsedExclusions : undefined,
      permitted_ports: parsedPorts.length > 0 ? parsedPorts : undefined,
      simulate_demo: !statusData?.nmap_available,
    });
  };

  const jobStatusTone = (status: string) => {
    if (status === "COMPLETED") return "positive";
    if (status === "COMPLETED_WITH_AMBIGUITY") return "info";
    if (status === "TOOL_UNAVAILABLE") return "medium";
    return "critical";
  };

  const serviceStateClass = (state: string) => {
    if (state === "OPEN") return "bg-positive-bg text-positive border-positive-border";
    if (state === "OPEN_OR_FILTERED") return "bg-low-bg text-low border-low-border";
    if (state === "FILTERED") return "bg-medium-bg text-medium border-medium-border";
    return "bg-info-bg text-info border-info-border";
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 border-b border-line pb-4">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight flex items-center gap-2">
            <Globe className="w-5 h-5 text-accent" />
            Authorized Asset Discovery
          </h1>
          <p className="text-[13px] text-ink-2">
            Safe, bounded Nmap service discovery for explicitly approved VPN endpoints.
          </p>
        </div>

        {/* Nmap Engine Status Indicator */}
        <div className="flex items-center gap-2">
          <div
            role="status"
            className="flex items-center gap-1.5 px-2.5 h-7 border border-line bg-panel text-xs"
          >
            <span
              className={`w-2 h-2 ${
                statusData?.nmap_available ? "bg-positive" : "bg-medium"
              }`}
            />
            <span className="font-mono text-ink-2">
              {isStatusLoading
                ? "Probing tool…"
                : statusData?.nmap_available
                ? `Nmap ${statusData.nmap_version || "ready"}`
                : "Nmap not installed (test mode)"}
            </span>
          </div>
          <ButtonLink href="/vulnerabilities" variant="secondary" size="sm">
            <ShieldAlert className="w-3.5 h-3.5 text-low" />
            <span>Vulnerability Reports</span>
          </ButtonLink>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetchJobs()}
            title="Refresh jobs"
            aria-label="Refresh jobs"
            className="px-1.5"
          >
            <RotateCw className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Safety & Ambiguity Callout */}
      <div className="border border-low-border bg-low-bg text-ink-2 flex items-start gap-3 p-4">
        <HelpCircle className="w-4 h-4 text-low shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-ink">
            Observational Evidence vs. Vulnerability Verdicts
          </div>
          <p className="text-[13px] leading-relaxed">
            Nmap discovery outputs scanner observations, not vulnerability claims or proof of VPN security.
            UDP service states such as <code className="font-mono font-semibold">open|filtered</code> occur when
            no response packet is returned (e.g. firewalls or non-responsive IKE responders). They remain
            explicitly ambiguous and are never converted into false certainty.
          </p>
        </div>
      </div>

      {/* Two-Column Grid: Form & Results */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Guided Workflow Form */}
        <div className="lg:col-span-5 space-y-5">
          <form onSubmit={handleOpenConfirmation} className="space-y-5">
            {/* §1 Target */}
            <Section index="§1" title="Target">
              <div className="space-y-4">
                <Field
                  label="Approved Targets (IPs, CIDRs, or hostnames)"
                  hint={`Max: ${statusData?.max_targets || 8}`}
                  required
                >
                  <Textarea
                    rows={2}
                    value={targetsText}
                    onChange={(e) => setTargetsText(e.target.value)}
                    placeholder="127.0.0.1, 10.0.0.1"
                    mono
                    required
                  />
                </Field>

                <div className="grid grid-cols-2 gap-3">
                  <Field label="Exclusions (optional)">
                    <Input
                      type="text"
                      value={exclusionsText}
                      onChange={(e) => setExclusionsText(e.target.value)}
                      placeholder="10.0.0.254"
                      mono
                    />
                  </Field>
                  <Field label="Ports (optional)">
                    <Input
                      type="text"
                      value={portsText}
                      onChange={(e) => setPortsText(e.target.value)}
                      placeholder="Default from profile"
                      mono
                    />
                  </Field>
                </div>
              </div>
            </Section>

            {/* §2 Discovery Profile */}
            <Section index="§2" title="Discovery Profile">
              <Field label="Bounded Scan Profile" required>
                <Select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                >
                  <option value="IKE_SERVICE_DISCOVERY">
                    IKE Service Discovery (UDP 500, 4500)
                  </option>
                  <option value="VPN_MANAGEMENT_DISCOVERY">
                    VPN Management Portals (TCP 22, 80, 443, 8443)
                  </option>
                  <option value="CUSTOM_BOUNDED">
                    Custom Bounded Scan (Operator-Specified Ports)
                  </option>
                </Select>
                <p className="text-xs text-ink-3">
                  {profile === "IKE_SERVICE_DISCOVERY" && "Low-impact UDP probe targeting standard IPsec and NAT-T ports."}
                  {profile === "VPN_MANAGEMENT_DISCOVERY" && "Safe TCP connect probes for authorized HTTPS, SSH, and management."}
                  {profile === "CUSTOM_BOUNDED" && "Strictly capped custom port probe (max 16 ports)."}
                </p>
              </Field>
            </Section>

            {/* §3 Authorization */}
            <Section index="§3" title="Authorization">
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Operator ID" required>
                    <Input
                      type="text"
                      value={operatorId}
                      onChange={(e) => setOperatorId(e.target.value)}
                      required
                    />
                  </Field>
                  <Field label="Auth Reference / Ticket" required>
                    <Input
                      type="text"
                      value={authRef}
                      onChange={(e) => setAuthRef(e.target.value)}
                      placeholder="e.g. CHG-2026-0924"
                      required
                    />
                  </Field>
                </div>

                <div className="border border-line bg-panel-2 p-3 space-y-2">
                  <label className="flex items-start gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={hasConfirmedAttestation}
                      onChange={(e) => setHasConfirmedAttestation(e.target.checked)}
                      className="mt-0.5 accent-accent"
                    />
                    <span className="text-[13px] text-ink font-medium leading-tight">
                      I explicitly attest that testing of these targets has been formally authorized by their legal owner.
                    </span>
                  </label>
                  <Textarea
                    rows={2}
                    value={authAttestation}
                    onChange={(e) => setAuthAttestation(e.target.value)}
                  />
                </div>
              </div>
            </Section>

            {/* §4 Review */}
            <Section index="§4" title="Review">
              <div className="border border-line bg-panel-2 p-3 font-mono text-xs text-ink-2 space-y-1.5">
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Profile:</span>
                  <span className="font-semibold text-ink text-right">{profile}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Targets:</span>
                  <span className="font-semibold text-ink text-right">{parsedTargets.join(", ")}</span>
                </div>
                {parsedExclusions.length > 0 && (
                  <div className="flex justify-between gap-3">
                    <span className="text-ink-3">Exclusions:</span>
                    <span className="text-ink text-right">{parsedExclusions.join(", ")}</span>
                  </div>
                )}
                {parsedPorts.length > 0 && (
                  <div className="flex justify-between gap-3">
                    <span className="text-ink-3">Ports:</span>
                    <span className="text-ink text-right">{parsedPorts.join(", ")}</span>
                  </div>
                )}
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Rate limit:</span>
                  <span className="text-ink text-right">{statusData?.rate_limit_pps || 100} pps (low impact)</span>
                </div>
              </div>
            </Section>

            {/* §5 Run */}
            <Section index="§5" title="Run">
              <div className="space-y-3">
                {formError && (
                  <div role="alert" className="border border-critical-border bg-critical-bg text-critical text-xs flex items-start gap-2 p-3">
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>{formError}</span>
                  </div>
                )}

                {!statusData?.nmap_available && (
                  <div className="border border-medium-border bg-medium-bg text-[13px] text-medium p-3 space-y-1">
                    <div className="font-semibold flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span>Nmap executable not found on host PATH</span>
                    </div>
                    <p className="text-xs text-ink-2 leading-relaxed">
                      Launching will run in <strong>Simulated Demo Mode</strong> to safely test service discovery,
                      XML parsing, and port mapping for IKE (500/udp) and NAT-T (4500/udp).
                    </p>
                  </div>
                )}

                <Button
                  type="submit"
                  variant="primary"
                  size="md"
                  disabled={!hasConfirmedAttestation || createJobMutation.isPending}
                  className="w-full"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>
                    {createJobMutation.isPending
                      ? "Submitting scan…"
                      : statusData?.nmap_available
                      ? "Review & Launch Discovery Scan"
                      : "Review & Launch Demo Scan"}
                  </span>
                </Button>
              </div>
            </Section>
          </form>

          {/* Job History List */}
          <Section
            title="Recent Discovery Jobs"
            actions={
              <span className="text-[11px] font-mono text-ink-3">
                {jobs?.length || 0} jobs
              </span>
            }
          >
            {isJobsLoading ? (
              <EmptyState compact title="Loading history…" />
            ) : !jobs || jobs.length === 0 ? (
              <EmptyState
                icon={<Globe />}
                title="No discovery jobs recorded yet"
                description="Launch an authorized assessment to begin."
              />
            ) : (
              <div className="space-y-1.5 max-h-64 overflow-y-auto">
                {jobs.map((job) => (
                  <button
                    key={job.id}
                    onClick={() => setSelectedJobId(job.id)}
                    aria-pressed={(selectedJobId || jobs[0]?.id) === job.id}
                    className={`w-full text-left p-2.5 border text-xs flex items-center justify-between gap-2 transition-colors ${
                      (selectedJobId || jobs[0]?.id) === job.id
                        ? "border-accent bg-accent-soft"
                        : "border-line hover:bg-panel-2"
                    }`}
                  >
                    <div className="truncate pr-2">
                      <div className="font-medium text-ink truncate">
                        {job.job_name}
                      </div>
                      <div className="text-[11px] text-ink-3 font-mono">
                        {job.profile} • {new Date(job.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                    <div className="shrink-0">
                      <span
                        className={`inline-flex items-center px-1.5 py-0.5 border text-[11px] font-mono uppercase font-semibold ${jobStatusTone(job.status)} ${
                          job.status === "COMPLETED" ? "bg-positive-bg text-positive border-positive-border"
                          : job.status === "COMPLETED_WITH_AMBIGUITY" ? "bg-low-bg text-low border-low-border"
                          : job.status === "TOOL_UNAVAILABLE" ? "bg-medium-bg text-medium border-medium-border"
                          : "bg-critical-bg text-critical border-critical-border"
                        }`}
                      >
                        {job.status}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </Section>
        </div>

        {/* Right Column: Active Job Results & Normalized Evidence */}
        <div className="lg:col-span-7 flex flex-col gap-5">
          {activeJob ? (
            <>
              {/* Job Header */}
              <Section title="Job Summary">
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-subhead font-semibold text-ink">
                          {activeJob.job_name}
                        </h3>
                        <StatusBadge status={activeJob.status} />
                      </div>
                      <div className="text-xs text-ink-3 font-mono mt-1">
                        ID: {activeJob.id}
                      </div>
                    </div>

                    {["QUEUED", "RUNNING", "VALIDATING"].includes(activeJob.status) && (
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => cancelJobMutation.mutate(activeJob.id)}
                        disabled={cancelJobMutation.isPending}
                      >
                        <Ban className="w-3.5 h-3.5" />
                        <span>Cancel Scan</span>
                      </Button>
                    )}
                  </div>

                  {/* Status Diagnostic Message */}
                  {activeJob.status === "TOOL_UNAVAILABLE" && (
                    <div className="border border-medium-border bg-medium-bg text-ink-2 text-xs space-y-1 p-3">
                      <div className="font-semibold text-medium flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Tool unavailable on this system</span>
                      </div>
                      <p className="text-[13px] leading-relaxed">
                        {activeJob.failure_reason ||
                          "Nmap executable was not found on PATH or configured NMAP_PATH. In local test mode, scanner integrations safely report tool absence rather than pretending execution succeeded."}
                      </p>
                    </div>
                  )}

                  {activeJob.status === "COMPLETED_WITH_AMBIGUITY" && (
                    <div className="border border-low-border bg-low-bg text-ink-2 text-xs space-y-1 p-3">
                      <div className="font-semibold text-low flex items-center gap-1.5">
                        <HelpCircle className="w-3.5 h-3.5" />
                        <span>Ambiguous port states observed</span>
                      </div>
                      <p className="text-[13px] leading-relaxed">
                        UDP probes against ports 500/4500 received no response, yielding <code className="font-mono font-semibold">open|filtered</code>.
                        This is standard network behavior for non-responding or protected IPsec endpoints and is preserved honestly.
                      </p>
                    </div>
                  )}

                  {/* Metrics Grid */}
                  <StatGrid className="sm:grid-cols-2 lg:grid-cols-4">
                    <Stat label="Target Count" value={activeJob.target_count} />
                    <Stat
                      label="Hosts Up"
                      value={activeJob.status === "TOOL_UNAVAILABLE" ? "Unavailable (not run)" : activeJob.hosts_up_count}
                      tone={activeJob.status === "TOOL_UNAVAILABLE" ? "medium" : "default"}
                    />
                    <Stat
                      label="Services Observed"
                      value={activeJob.status === "TOOL_UNAVAILABLE" ? "Unavailable (not run)" : activeJob.services_discovered_count}
                      tone={activeJob.status === "TOOL_UNAVAILABLE" ? "medium" : "default"}
                    />
                    <Stat label="Nmap Version" value={activeJob.tool_version || "N/A"} />
                  </StatGrid>

                  {/* Provenance Details */}
                  <div className="border-t border-line pt-3 text-xs space-y-1.5 font-mono text-ink-3">
                    <div className="flex justify-between gap-3">
                      <span>Operator:</span>
                      <span className="text-ink font-semibold">{activeJob.operator_id}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span>Auth Reference:</span>
                      <span className="text-ink">{activeJob.authorization_reference}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span>Canonical Targets:</span>
                      <span className="text-ink truncate max-w-xs">{activeJob.canonical_targets.join(", ")}</span>
                    </div>
                    {activeJob.raw_output_sha256 && (
                      <div className="flex justify-between items-center gap-3">
                        <span>XML SHA-256:</span>
                        <span className="text-ink truncate max-w-xs">{activeJob.raw_output_sha256}</span>
                      </div>
                    )}
                  </div>
                </div>
              </Section>

              {/* Discovered Hosts & Services Evidence Table */}
              <Section
                title="Normalized Scanner Observations"
                actions={
                  <span className="text-[11px] font-mono text-ink-3">
                    Zero fabrication policy
                  </span>
                }
              >
                {activeJob.hosts.length === 0 ? (
                  <EmptyState
                    fill
                    icon={<Terminal />}
                    title={activeJob.status === "TOOL_UNAVAILABLE"
                      ? "No scan observations (Nmap unavailable on host)"
                      : "No host observations recorded for this run"}
                    description="Scanner output will appear here once a job completes."
                  />
                ) : (
                  <div className="space-y-4">
                    {activeJob.hosts.map((host) => (
                      <div key={host.id} className="border border-line overflow-hidden">
                        {/* Host Header */}
                        <div className="px-3 py-2.5 bg-panel-2 border-b border-line flex items-center justify-between gap-2 text-xs font-mono">
                          <div className="flex items-center gap-2 min-w-0">
                            <span
                              className={`w-2 h-2 shrink-0 ${
                                host.state === "UP" ? "bg-positive" : "bg-critical"
                              }`}
                            />
                            <span className="font-semibold text-ink">
                              {host.ip_address}
                            </span>
                            <span className="text-ink-3">({host.ip_version})</span>
                            {host.hostnames && host.hostnames.length > 0 && (
                              <span className="text-ink-3 truncate">
                                [{host.hostnames.join(", ")}]
                              </span>
                            )}
                          </div>
                          <span
                            className={`px-1.5 py-0.5 border text-[11px] font-semibold shrink-0 ${
                              host.state === "UP"
                                ? "bg-positive-bg text-positive border-positive-border"
                                : "bg-critical-bg text-critical border-critical-border"
                            }`}
                          >
                            State: {host.state}
                          </span>
                        </div>

                        {/* Services Table */}
                        {host.services.length === 0 ? (
                          <div className="p-4 text-center text-xs text-ink-3 font-mono">
                            No open/observed services found on this host
                          </div>
                        ) : (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Port</TableHead>
                                <TableHead>Proto</TableHead>
                                <TableHead>Observed State</TableHead>
                                <TableHead>Reason</TableHead>
                                <TableHead>Service / Banner</TableHead>
                                <TableHead>Product / Version</TableHead>
                                <TableHead>Conf</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {host.services.map((svc) => (
                                <TableRow key={svc.id}>
                                  <TableCell mono className="font-semibold text-ink">
                                    {svc.port}
                                  </TableCell>
                                  <TableCell mono>{svc.protocol}</TableCell>
                                  <TableCell mono>
                                    <span className={`inline-flex items-center px-1.5 py-0.5 border text-[11px] font-semibold ${serviceStateClass(svc.state)}`}>
                                      {svc.state}
                                    </span>
                                  </TableCell>
                                  <TableCell mono className="text-ink-3">
                                    {svc.state_reason || "unknown"}
                                  </TableCell>
                                  <TableCell mono className="font-semibold">
                                    {svc.service_name || "unknown"}
                                  </TableCell>
                                  <TableCell mono className="text-ink-3">
                                    {[svc.product, svc.version].filter(Boolean).join(" ") || "—"}
                                  </TableCell>
                                  <TableCell mono className="text-ink-3">
                                    {svc.confidence !== null ? `${svc.confidence}` : "—"}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Section>
            </>
          ) : (
            <EmptyState
              fill
              icon={<Globe />}
              title="Select a discovery job or launch a new authorized assessment"
              description="Job results and normalized scanner observations will appear here."
            />
          )}
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="w-full max-w-lg border border-line bg-panel p-5 space-y-4 text-xs">
            <div className="flex items-center gap-2 text-ink border-b border-line pb-3">
              <ShieldAlert className="w-5 h-5 text-accent" />
              <h3 className="text-sm font-semibold">
                Confirm Authorized Scope Execution
              </h3>
            </div>

            <div className="space-y-3 font-mono">
              <div className="border border-line bg-panel-2 p-3 space-y-1.5">
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Profile:</span>
                  <span className="font-semibold text-ink">{profile}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Operator:</span>
                  <span className="text-ink">{operatorId}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Auth Ref:</span>
                  <span className="text-ink">{authRef}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Expanded Targets:</span>
                  <span className="font-semibold text-ink text-right">{parsedTargets.join(", ")}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-ink-3">Rate Limit:</span>
                  <span className="text-ink">
                    {statusData?.rate_limit_pps || 100} pps (Low Impact)
                  </span>
                </div>
              </div>

              <p className="text-[13px] text-ink-2 leading-relaxed">
                By confirming, you attest that you hold explicit legal authorization to discover network services on
                these targets. All actions and output digests are permanently recorded in the audit trail.
              </p>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setShowConfirmModal(false)}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleExecuteScan}
                disabled={createJobMutation.isPending}
              >
                <Play className="w-3.5 h-3.5" />
                <span>Confirm & Launch</span>
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
