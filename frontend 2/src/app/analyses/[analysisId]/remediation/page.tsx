"use client";

import React, { use, useState, useEffect } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  ProjectedFindingDTO,
  RemediationRunStepDTO,
  SemanticDiffItemDTO,
  VerificationClaimDTO,
} from "@/lib/api/types";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Section, Subsection } from "@/components/ui/section";
import { Tabs } from "@/components/ui/tabs";
import { EmptyState } from "@/components/ui/empty-state";
import { StatusBadge, EvidenceStateBadge } from "@/components/ui/badge";
import { Field, Input, Textarea } from "@/components/ui/input";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableCell,
  TableHead,
} from "@/components/ui/table";
import {
  SlidersHorizontal,
  AlertTriangle,
  ShieldCheck,
  Play,
  ArrowRight,
  Lock,
  Activity,
  ChevronDown,
  ChevronRight,
  RefreshCw,
} from "lucide-react";

export default function RemediationTwinPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"twin" | "semantic_diff" | "text_diff" | "audit" | "claims">("twin");
  const [activeViewMode, setActiveViewMode] = useState<"side_by_side" | "diff_first">("side_by_side");
  const [editedConfig, setEditedConfig] = useState<string>("");
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
  const [confirmControlledLab, setConfirmControlledLab] = useState(false);
  const [operatorId, setOperatorId] = useState<string>("analyst-local");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [expandedClaimId, setExpandedClaimId] = useState<string | null>(null);
  const hasInitializedConfigRef = React.useRef(false);

  // 1. Fetch Twin
  const {
    data: twin,
    isLoading: isTwinLoading,
    refetch: refetchTwin,
  } = useQuery({
    queryKey: ["remediation-twin", analysisId],
    queryFn: () => api.remediation.getTwin(analysisId),
  });

  // Sync edited config once twin loads
  useEffect(() => {
    if (twin?.rendered_proposed_config && !hasInitializedConfigRef.current) {
      setEditedConfig(twin.rendered_proposed_config);
      hasInitializedConfigRef.current = true;
    }
  }, [twin?.rendered_proposed_config]);

  // 2. Fetch Latest Verification
  const { data: latestVerification, refetch: refetchVerification } = useQuery({
    queryKey: ["latest-verification", analysisId],
    queryFn: () => api.remediation.getLatestVerification(analysisId),
    refetchInterval: activeRunId ? 2500 : false,
  });

  // 3. Poll Run if active
  const { data: activeRun } = useQuery({
    queryKey: ["remediation-run", analysisId, activeRunId],
    queryFn: () => api.remediation.getRun(analysisId, activeRunId!),
    enabled: !!activeRunId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && (data.status === "COMPLETED" || data.status === "FAILED" || data.status === "ROLLED_BACK" || data.status === "ROLLBACK_FAILED")) {
        return false;
      }
      return 1500;
    },
  });

  // 4. Preflight query
  const { data: preflight, refetch: refetchPreflight } = useQuery({
    queryKey: ["remediation-preflight", analysisId, twin?.twin_id, twin?.proposal_hash],
    queryFn: () => api.remediation.runPreflight(analysisId, twin!.twin_id, twin!.proposal_hash),
    enabled: !!twin?.twin_id && !!twin?.proposal_hash,
  });

  // 5. Update proposal mutation
  const updateProposalMutation = useMutation({
    mutationFn: (text: string) => api.remediation.updateProposal(analysisId, text),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediation-twin", analysisId] });
      refetchPreflight();
    },
  });

  // 6. Apply remediation mutation
  const applyMutation = useMutation({
    mutationFn: () =>
      api.remediation.apply(analysisId, {
        twin_id: twin!.twin_id,
        proposal_hash: twin!.proposal_hash,
        lab_instance_id: "strongswan-lab-default",
        operator_id: operatorId || "analyst-local",
        confirm_controlled_lab_only: true,
      }),
    onSuccess: (data) => {
      setActiveRunId(data.run_id);
      setIsConfirmModalOpen(false);
      setConfirmControlledLab(false);
    },
  });

  const isExecuting = activeRun && !["COMPLETED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED"].includes(activeRun.status);

  if (isTwinLoading) {
    return (
      <EmptyState
        compact
        icon={<SlidersHorizontal className="w-5 h-5" />}
        title="Simulating counterfactual security twin and rendering proposed swanctl.conf…"
      />
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight">
            Configuration Security Twin &amp; Closed-Loop Remediation
          </h1>
          <p className="text-[13px] text-ink-2">
            Simulated strongSwan/Libreswan configuration changes to remediate cryptographic
            weaknesses. Projected score uplift is computed before applying, and fixes are verified
            in an isolated testbed before any production deployment.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              refetchTwin();
              refetchVerification();
              refetchPreflight();
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </Button>

          <Button
            variant="primary"
            size="sm"
            disabled={!preflight?.is_ready || isExecuting}
            onClick={() => setIsConfirmModalOpen(true)}
          >
            <Play className="w-3.5 h-3.5" />
            <span>Validate in Controlled Lab</span>
          </Button>
        </div>
      </div>

      {/* §1 Epistemic Principle */}
      <Section index="§1" title="Closed-Loop Verification Principle">
        <div className="border-l-2 border-accent bg-panel-2 p-3.5 space-y-1.5">
          <div className="flex items-center gap-2 text-[13px] font-semibold text-ink">
            <Activity className="w-4 h-4 text-accent shrink-0" />
            <span>Simulated model — not final proof</span>
          </div>
          <p className="text-[13px] text-ink-2 leading-relaxed">
            The <strong>Configuration Security Twin is a simulated what-if model</strong>, not final proof.
            Only applying the proposed configuration to an isolated Linux namespace strongSwan testbed, establishing a fresh Security Association, generating synthetic traffic, and re-analyzing fresh packet capture creates <strong>VERIFIED</strong> remediation claims.
          </p>
        </div>
      </Section>

      {/* §2 Live Remediation Run Execution (if active or recently finished) */}
      {(activeRun || isExecuting) && (
        <Section
          index="§2"
          title={`Remediation Run #${activeRun?.run_id?.slice(0, 8)}`}
          actions={activeRun?.status ? <StatusBadge status={activeRun.status} /> : undefined}
        >
          <div className="border border-line bg-panel p-4 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-mono text-ink-3">
                Lab Target: <span className="font-semibold text-ink-2">{activeRun?.lab_instance_id}</span>
              </span>
              <span className="font-mono text-ink-3">
                Operator: <span className="font-semibold text-ink-2">{activeRun?.operator_id}</span>
              </span>
            </div>

            {/* SAGA Step Progress */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2 pt-3 border-t border-line">
              {activeRun?.steps?.map((step: RemediationRunStepDTO) => (
                <div
                  key={step.sequence}
                  className={`p-2 border text-[11px] ${
                    step.status === "SUCCESS"
                      ? "border-positive-border bg-positive-bg text-positive"
                      : step.status === "FAILED"
                      ? "border-critical-border bg-critical-bg text-critical"
                      : step.status === "RUNNING"
                      ? "border-medium-border bg-medium-bg text-medium"
                      : "border-line text-ink-3"
                  }`}
                >
                  <div className="font-semibold uppercase truncate">{step.action_type}</div>
                  <div className="text-[11px] mt-0.5 opacity-80">{step.status}</div>
                </div>
              ))}
            </div>

            {activeRun?.status === "ROLLBACK_FAILED" ? (
              <div className="p-3 bg-critical-bg border border-critical-border text-critical space-y-1">
                <div className="flex items-center gap-2 text-[13px] font-semibold">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>Critical: Rollback Verification Failed</span>
                </div>
                <p className="text-xs">
                  Automatic restoration could not be fully verified against baseline configuration digests. <strong>Manual lab testbed intervention required.</strong>
                </p>
                {activeRun?.error_message && <p className="text-[11px] font-mono">{activeRun.error_message}</p>}
              </div>
            ) : activeRun?.rollback_state !== "NONE" ? (
              <div className="p-2.5 bg-medium-bg border border-medium-border text-medium text-xs">
                <span className="font-semibold">Automatic Rollback State:</span> {activeRun?.rollback_state}
                {activeRun?.rollback_reason && <p className="text-[11px] mt-0.5">{activeRun?.rollback_reason}</p>}
              </div>
            ) : null}

            {activeRun?.post_capture_hash && (
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-ink-3 pt-1 border-t border-line font-mono">
                <span>
                  Verified PCAP Digest: <span className="font-semibold text-ink-2">{activeRun.post_capture_hash.slice(0, 16)}...</span>
                </span>
                {activeRun.pre_apply_spis && <span>Pre-Apply SAs: {activeRun.pre_apply_spis.length} observed</span>}
              </div>
            )}
          </div>
        </Section>
      )}

      {/* §3 Remediation Workbench */}
      <Section
        index="§3"
        title="Remediation Workbench"
        description="Compare the observed configuration against the security twin proposal, inspect projected regression impact, and review verified claims."
      >
        <Tabs
          items={[
            { id: "twin", label: "Twin Workbench" },
            { id: "semantic_diff", label: "Security Semantic Diff" },
            { id: "text_diff", label: "swanctl.conf Text Diff" },
            { id: "audit", label: "Projected Regression Audit" },
            { id: "claims", label: "Verification Claim Ledger" },
          ]}
          active={activeTab}
          onChange={(id) => setActiveTab(id as typeof activeTab)}
        />

        {/* Tab 1: Twin Workbench (3-Column Progression: Current -> Projected -> Verified) */}
        {activeTab === "twin" && (
          <div className="space-y-4">
            {/* Baseline Linkage Status Notice / Unassessable Notice */}
            {twin && !twin.has_linked_baseline && (
              (twin.projected_score == null || twin.projected_regression_audit?.baseline_score == null) ? (
                <div className="p-3.5 bg-medium-bg border border-medium-border text-medium space-y-2">
                  <div className="flex items-center gap-2 text-[13px] font-semibold">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>Configuration Posture Not Assessable</span>
                  </div>
                  <p className="text-xs leading-relaxed">
                    This capture does not contain observed IKE negotiation exchanges or a linked configuration baseline.
                    Cryptographic configuration posture cannot be verified from encrypted payload frames alone without handshake parameters or authoritative gateway configurations.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 pt-1">
                    <Link
                      href="/lab"
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-accent-ink hover:underline"
                    >
                      <span>Evaluate in Controlled Lab</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                    <span className="text-ink-3">|</span>
                    <Link
                      href="/analyses/new"
                      className="text-xs font-semibold text-ink-2 hover:underline"
                    >
                      Ingest Handshake Capture
                    </Link>
                  </div>
                </div>
              ) : (
                <div className="p-3.5 bg-medium-bg border border-medium-border text-medium space-y-1">
                  <div className="flex items-center gap-2 text-[13px] font-semibold">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>No Linked Configuration Baseline</span>
                  </div>
                  <p className="text-xs leading-relaxed">
                    This capture analysis is not linked to an approved configuration file in Configuration &amp; Certificate Inventory.
                    The observable properties and baseline score below were derived solely from observed PCAP wire metadata. Counterfactual configuration projections represent synthetic models until an authoritative gateway configuration file is imported.
                  </p>
                </div>
              )
            )}
            {twin && twin.has_linked_baseline && twin.baseline_provenance && (
              <div className="p-3 bg-positive-bg border border-positive-border text-positive text-xs flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 shrink-0" />
                <span>Linked Configuration Baseline: <strong>{twin.baseline_provenance}</strong></span>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* COLUMN 1: CURRENT OBSERVED */}
              <div className="border border-line bg-panel p-4 space-y-4">
                <div className="border-b border-line pb-2 flex items-start justify-between gap-2">
                  <div>
                    <span className="px-2 py-0.5 bg-panel-2 border border-line text-ink-2 text-[11px] font-mono font-semibold uppercase tracking-wide">
                      {twin?.has_linked_baseline ? "Approved Gateway Baseline" : "Wire-Observed PCAP Facts"}
                    </span>
                    <h3 className="font-semibold text-sm text-ink mt-1.5">
                      1. Observed Model
                    </h3>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-[11px] text-ink-3">Baseline Score</div>
                    <div className="text-xs font-semibold text-ink">
                      {twin?.projected_regression_audit?.baseline_score != null
                        ? `${twin.projected_regression_audit.baseline_score}/100`
                        : "UNKNOWN / NOT ASSESSABLE"}
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-[11px] font-semibold text-ink-3 uppercase tracking-wide">
                    {twin?.has_linked_baseline ? "Configured Properties" : "Observable Wire Properties"}
                  </div>
                  {twin?.semantic_diff?.map((prop: SemanticDiffItemDTO) => (
                    <div key={prop.field} className="p-2 border border-line bg-panel-2 space-y-1">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="text-ink-3">{prop.label}:</span>
                        <span className="font-mono font-semibold text-ink">{String(prop.current_value)}</span>
                      </div>
                      <div className="flex items-center justify-between gap-2 text-[11px]">
                        <span className="text-ink-3">Evidence State:</span>
                        <EvidenceStateBadge state={prop.current_evidence_state} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* COLUMN 2: PROJECTED PROPOSED */}
              <div className="border-2 border-accent bg-panel p-4 space-y-4">
                <div className="border-b border-line pb-2 flex items-start justify-between gap-2">
                  <div>
                    <span className="px-2 py-0.5 bg-accent-press text-on-accent text-[11px] font-mono font-semibold uppercase tracking-wide">
                      Projected (Counterfactual)
                    </span>
                    <h3 className="font-semibold text-sm text-ink mt-1.5">
                      2. Security Twin Proposal
                    </h3>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-[11px] text-ink-3">Projected Delta</div>
                    <div className="text-xs font-semibold text-positive">
                      {twin?.projected_score_delta != null
                        ? (twin.projected_score_delta > 0
                            ? `+${twin.projected_score_delta}`
                            : twin.projected_score_delta === 0
                            ? "0 (No Deficiencies)"
                            : `${twin.projected_score_delta}`)
                        : (twin && !twin.has_linked_baseline && (twin.projected_score == null || twin.projected_regression_audit?.baseline_score == null))
                        ? "NOT ASSESSABLE"
                        : "—"}
                    </div>
                  </div>
                </div>

                {/* Proposal Hash Lineage */}
                <div className="p-2 bg-panel-2 border border-line text-[11px] font-mono space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-ink-3 uppercase">Immutable Hash:</span>
                    <span className="font-semibold text-ink truncate max-w-[180px]">
                      {twin?.proposal_hash}
                    </span>
                  </div>
                </div>

                {/* Editable Configuration Buffer */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] text-ink-3 font-semibold uppercase tracking-wide">
                      swanctl.conf proposal template
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => updateProposalMutation.mutate(editedConfig)}
                      disabled={updateProposalMutation.isPending || editedConfig === twin?.rendered_proposed_config}
                      aria-live="polite"
                    >
                      {updateProposalMutation.isPending ? "Re-projecting..." : "Re-project Changes"}
                    </Button>
                  </div>
                  <Textarea
                    mono
                    value={editedConfig}
                    onChange={(e) => setEditedConfig(e.target.value)}
                    rows={14}
                    className="text-xs leading-relaxed"
                  />
                </div>
              </div>

              {/* COLUMN 3: VERIFIED POST-REMEDIATION */}
              <div className="border border-line bg-panel p-4 space-y-4">
                <div className="border-b border-line pb-2 flex items-start justify-between gap-2">
                  <div>
                    <span className="px-2 py-0.5 bg-positive-bg border border-positive-border text-positive text-[11px] font-mono font-semibold uppercase tracking-wide">
                      Verified (Empirical Wire Evidence)
                    </span>
                    <h3 className="font-semibold text-sm text-ink mt-1.5">
                      3. Lab Verification
                    </h3>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-[11px] text-ink-3">Verified Score</div>
                    <div className="text-sm font-semibold text-positive">
                      {latestVerification?.verified_score ?? "Pending Run"}
                    </div>
                  </div>
                </div>

                {latestVerification ? (
                  <div className="space-y-3">
                    {/* Dual-Axis Result */}
                    <div className="grid grid-cols-2 gap-2 text-center">
                      <div className="p-2 border border-positive-border bg-positive-bg text-positive">
                        <div className="text-[11px] uppercase font-semibold text-ink-3">Security Outcome</div>
                        <div className="font-semibold text-xs mt-0.5">{latestVerification.security_result}</div>
                      </div>
                      <div className="p-2 border border-positive-border bg-positive-bg text-positive">
                        <div className="text-[11px] uppercase font-semibold text-ink-3">Operational Transit</div>
                        <div className="font-semibold text-xs mt-0.5">{latestVerification.operational_result}</div>
                      </div>
                    </div>

                    {/* Summary */}
                    <div className="p-2.5 bg-panel-2 border border-line text-xs space-y-1">
                      <div className="text-ink-3 uppercase text-[11px] font-semibold tracking-wide">Verification Overview</div>
                      <div className="text-ink-2">
                        {latestVerification.verification_result}
                      </div>
                      <div className="text-ink-3 text-[11px]">
                        Verified at: {new Date(latestVerification.verified_at).toLocaleTimeString()}
                      </div>
                    </div>

                    {/* Claims quick summary */}
                    <div className="space-y-1.5">
                      <div className="text-[11px] font-semibold text-ink-3 uppercase tracking-wide">
                        Itemized Claims ({latestVerification.claims.length})
                      </div>
                      {latestVerification.claims.map((claim: VerificationClaimDTO) => (
                        <div
                          key={claim.claim_id}
                          className="p-2 border border-line bg-panel-2 flex items-center justify-between gap-2 text-xs"
                        >
                          <span className="font-mono font-semibold truncate max-w-[150px]">{claim.rule_id}</span>
                          <span className="px-2 py-0.5 bg-positive-bg border border-positive-border text-positive font-semibold text-[11px] shrink-0">
                            {claim.claim_result}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    compact
                    icon={<Lock className="w-5 h-5" />}
                    title="No Verified Run Yet"
                    description="Run &quot;Validate in Controlled Lab&quot; above to execute the closed-loop apply → fresh packet capture cycle."
                  />
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Security Semantic Diff */}
        {activeTab === "semantic_diff" && (
          <Card title="Security Semantic Diff (Configuration IR Changes)" padded={false}>
            <Table>
              <TableHeader>
                <tr>
                  <TableHead>Property</TableHead>
                  <TableHead>Baseline Observed</TableHead>
                  <TableHead>Evidence State</TableHead>
                  <TableHead>Proposed (Hardened)</TableHead>
                  <TableHead>Policy Rationale &amp; Impact</TableHead>
                </tr>
              </TableHeader>
              <TableBody>
                {twin?.semantic_diff?.map((diff: SemanticDiffItemDTO) => (
                  <TableRow key={diff.field} className={diff.is_changed ? "bg-accent-soft" : ""}>
                    <TableCell className="font-semibold text-ink">{diff.label}</TableCell>
                    <TableCell mono>{String(diff.current_value)}</TableCell>
                    <TableCell>
                      <EvidenceStateBadge state={diff.current_evidence_state} />
                    </TableCell>
                    <TableCell mono className="font-semibold text-accent-ink">{String(diff.proposed_value)}</TableCell>
                    <TableCell className="text-ink-3 text-xs">{diff.policy_impact}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}

        {/* Tab 3: swanctl.conf Unified Text Diff */}
        {activeTab === "text_diff" && (
          <Card title="Unified Text Diff (strongSwan swanctl.conf)">
            <pre className="p-4 bg-panel-3 text-ink-2 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed border border-line">
              {twin?.text_diff || "No textual differences detected."}
            </pre>
          </Card>
        )}

        {/* Tab 4: Projected Regression Audit */}
        {activeTab === "audit" && (
          <div className="space-y-4">
            <Card title="Projected Regression Audit (Whole-Policy Evaluation)">
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3 border border-positive-border bg-positive-bg text-positive">
                    <div className="text-[11px] font-semibold uppercase tracking-wide">Projected Resolved Findings</div>
                    <div className="text-2xl font-mono font-bold mt-1">
                      {twin?.projected_regression_audit?.projected_resolved_findings?.length || 0}
                    </div>
                  </div>
                  <div className="p-3 border border-line bg-panel-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">Unaddressed Findings</div>
                    <div className="text-2xl font-mono font-bold text-ink mt-1">
                      {twin?.projected_regression_audit?.projected_remaining_findings?.length || 0}
                    </div>
                  </div>
                  <div className="p-3 border border-critical-border bg-critical-bg text-critical">
                    <div className="text-[11px] font-semibold uppercase tracking-wide">New Projected Regressions</div>
                    <div className="text-2xl font-mono font-bold mt-1">
                      {twin?.projected_regression_audit?.projected_new_regressions?.length || 0}
                    </div>
                  </div>
                </div>

                {/* Resolved Items */}
                <Subsection title="Targeted Findings Projected Resolved">
                  <div className="space-y-2">
                    {twin?.projected_regression_audit?.projected_resolved_findings?.map((item: ProjectedFindingDTO) => (
                      <div key={item.finding_id} className="p-2.5 border border-positive-border bg-positive-bg flex items-center justify-between gap-3">
                        <div>
                          <span className="font-mono font-semibold text-ink">{item.rule_id}</span>
                          <span className="text-ink-2"> — {item.title}</span>
                          <p className="text-[11px] text-ink-3 mt-0.5">{item.rationale}</p>
                        </div>
                        <span className="px-2 py-0.5 bg-positive-bg border border-positive-border text-positive font-semibold text-[11px] uppercase shrink-0">
                          {item.projected_state}
                        </span>
                      </div>
                    ))}
                  </div>
                </Subsection>
              </div>
            </Card>
          </div>
        )}

        {/* Tab 5: Verification Claim Ledger */}
        {activeTab === "claims" && (
          <Card title="Verification Claim Ledger (Finding-Level Proof Audit)">
            {latestVerification?.claims?.length ? (
              <div className="space-y-3">
                {latestVerification.claims.map((claim: VerificationClaimDTO) => {
                  const isExpanded = expandedClaimId === claim.claim_id;
                  return (
                    <div
                      key={claim.claim_id}
                      className="border border-line overflow-hidden"
                    >
                      <button
                        onClick={() => setExpandedClaimId(isExpanded ? null : claim.claim_id)}
                        aria-expanded={isExpanded}
                        className="w-full p-3 bg-panel-2 flex items-center justify-between gap-2 text-left hover:bg-panel-3 transition-colors"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          {isExpanded ? <ChevronDown className="w-4 h-4 text-accent shrink-0" /> : <ChevronRight className="w-4 h-4 text-ink-3 shrink-0" />}
                          <span className="font-mono font-semibold text-ink">{claim.rule_id}</span>
                          <span className="text-ink-3 text-xs truncate">({claim.root_cause_key})</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="px-2 py-0.5 bg-positive-bg border border-positive-border text-positive font-semibold text-[11px]">
                            {claim.claim_result}
                          </span>
                        </div>
                      </button>

                      {isExpanded && (
                        <div className="p-4 bg-panel border-t border-line space-y-3 text-xs">
                          <div>
                            <span className="font-semibold uppercase text-ink-3 tracking-wide">Formal Verification Criterion:</span>
                            <p className="text-ink-2 mt-0.5">{claim.expected_condition}</p>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-line">
                            <div className="p-2.5 bg-panel-2 border border-line">
                              <span className="font-semibold uppercase text-ink-3 text-[11px] tracking-wide">Baseline Wire Evidence</span>
                              <pre className="mt-1 text-[11px] overflow-x-auto text-ink-2 font-mono">
                                {JSON.stringify(claim.baseline_evidence, null, 2)}
                              </pre>
                            </div>
                            <div className="p-2.5 bg-positive-bg border border-positive-border">
                              <span className="font-semibold uppercase text-positive text-[11px] tracking-wide">Post-Remediation Evidence Frame</span>
                              <pre className="mt-1 text-[11px] overflow-x-auto text-positive font-mono">
                                {JSON.stringify(claim.post_evidence, null, 2)}
                              </pre>
                            </div>
                          </div>

                          <div className="text-[11px] text-ink-3 font-mono">
                            Reason Code: <strong className="text-ink-2">{claim.reason_code}</strong>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState
                compact
                title="No claim ledger entries"
                description="Verification claims are populated upon lab execution."
              />
            )}
          </Card>
        )}
      </Section>

      {/* Explicit Hash-Bound Approval Modal */}
      {isConfirmModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Operator authorization gate">
          <div className="bg-panel border-2 border-accent max-w-xl w-full p-5 space-y-4">
            <div className="flex items-center gap-2 text-accent-ink font-semibold text-sm">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <span>Operator Authorization Gate — Controlled Lab Apply</span>
            </div>

            <p className="text-ink-2 leading-relaxed text-[13px]">
              You are about to deploy configuration proposal <strong className="font-mono">{twin?.proposal_hash.slice(0, 16)}...</strong> to the isolated strongSwan testbed. This action will:
            </p>

            <ul className="list-disc pl-5 space-y-1 text-ink-3 text-xs">
              <li>Acquire exclusive testbed lock (`lab.lock`).</li>
              <li>Create an immutable pre-remediation backup of the active daemon configuration.</li>
              <li>Atomically overwrite `swanctl.conf` inside the Linux namespace.</li>
              <li>Reload strongSwan and renegotiate a fresh Security Association.</li>
              <li>Execute synthetic traffic to verify data plane packet transit.</li>
              <li>Capture a fresh verification PCAP and run full Stages 3–8 analysis.</li>
              <li>Automatically rollback if the tunnel negotiation or daemon crashes.</li>
            </ul>

            <div className="p-3 bg-panel-2 border border-line text-xs space-y-3">
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div>
                  <span className="text-ink-3 uppercase block text-[11px] tracking-wide">Proposal Digest (SHA-256):</span>
                  <span className="text-ink font-semibold">{twin?.proposal_hash.slice(0, 20)}...</span>
                </div>
                <div>
                  <span className="text-ink-3 uppercase block text-[11px] tracking-wide">Lab Sandbox Target:</span>
                  <span className="text-ink font-semibold">strongswan-lab-default</span>
                </div>
              </div>

              <Field label="Authorizing Operator Identifier" hint="e.g. security-engineer-1">
                <Input
                  mono
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                  placeholder="e.g. security-engineer-1"
                />
              </Field>

              <label className="flex items-start gap-2 cursor-pointer pt-1 border-t border-line">
                <input
                  type="checkbox"
                  checked={confirmControlledLab}
                  onChange={(e) => setConfirmControlledLab(e.target.checked)}
                  className="mt-0.5 h-4 w-4 accent-accent"
                />
                <span className="font-semibold text-ink text-xs">
                  I confirm this action targets the controlled strongSwan testbed only. No external production or vendor device will be mutated.
                </span>
              </label>
            </div>

            <p className="text-[11px] text-ink-3">
              * Approval is bound cryptographically to this exact proposal hash, diff hash, and fresh authorization timestamp. Any subsequent edit immediately revokes authorization.
            </p>

            <div className="flex items-center justify-end gap-2 pt-2">
              <Button
                variant="secondary"
                onClick={() => {
                  setIsConfirmModalOpen(false);
                  setConfirmControlledLab(false);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                disabled={!confirmControlledLab || applyMutation.isPending}
                onClick={() => applyMutation.mutate()}
                aria-live="polite"
              >
                {applyMutation.isPending ? "Applying..." : "Authorize & Execute"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
