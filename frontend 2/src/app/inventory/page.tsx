"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  ConfigurationSnapshotDTO,
  ConfigurationDriftDTO,
  GatewayCertificateDTO,
} from "@/lib/api/types";
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
import { Section } from "@/components/ui/section";
import { Subsection } from "@/components/ui/section";
import { Tabs } from "@/components/ui/tabs";
import { Stat, StatGrid } from "@/components/ui/stat";
import { EmptyState } from "@/components/ui/empty-state";
import { Button, ButtonLink } from "@/components/ui/button";
import { Field, Input, Textarea, Select } from "@/components/ui/input";
import { StateText } from "@/components/ui/badge";
import {
  FileKey2,
  FileCode2,
  GitCompare,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  PlusCircle,
  Eye,
  CheckCircle2,
  Radio,
  Activity,
  Layers,
  Loader2,
} from "lucide-react";

function InventoryContent() {
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();

  // Navigation tab state
  const [activeTab, setActiveTab] = useState<"snapshots" | "drift" | "certificates" | "import">("snapshots");

  // Filter states
  const [selectedGateway, setSelectedGateway] = useState<string>("");
  const [certValidityFilter, setCertValidityFilter] = useState<string>("");

  // Sync selectedGateway from URL query parameter if present
  useEffect(() => {
    const gwParam = searchParams.get("gateway_identity");
    if (gwParam) {
      setSelectedGateway(gwParam);
    }
  }, [searchParams]);

  // Drawer inspector states
  const [selectedSnapshot, setSelectedSnapshot] = useState<ConfigurationSnapshotDTO | null>(null);
  const [selectedDrift, setSelectedDrift] = useState<ConfigurationDriftDTO | null>(null);
  const [selectedCert, setSelectedCert] = useState<GatewayCertificateDTO | null>(null);

  // Drift comparison form state
  const [driftBaselineId, setDriftBaselineId] = useState<string>("");
  const [driftObservedId, setDriftObservedId] = useState<string>("");

  // Ingestion form state
  const [importType, setImportType] = useState<"config" | "cert">("config");
  const [gatewayIdentity, setGatewayIdentity] = useState("gw-strongswan-01");
  const [authorizedScope, setAuthorizedScope] = useState("198.51.100.0/24");
  const [sourceType, setSourceType] = useState<"CONFIGURED_FILE" | "LAB_CONTROLLED">("CONFIGURED_FILE");
  const [configText, setConfigText] = useState("");
  const [certPemText, setCertPemText] = useState("");
  const [trustStorePemText, setTrustStorePemText] = useState("");
  const [sourceAlias, setSourceAlias] = useState("gateway_swanctl.conf");
  const [operatorId, setOperatorId] = useState("operator-admin");
  const [authRef, setAuthRef] = useState("CHG-2026-INV-01");
  const [attestationConfirmed, setAttestationConfirmed] = useState(false);
  const [formMessage, setFormMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Queries
  const {
    data: snapshots = [],
    isLoading: isSnapshotsLoading,
    refetch: refetchSnapshots,
  } = useQuery({
    queryKey: ["inventory-snapshots", selectedGateway],
    queryFn: () =>
      api.inventory.listSnapshots({
        gateway_identity: selectedGateway || undefined,
        limit: 50,
      }),
  });

  const {
    data: driftHistory = [],
    isLoading: isDriftLoading,
    refetch: refetchDrift,
  } = useQuery({
    queryKey: ["inventory-drift-history", selectedGateway],
    queryFn: () =>
      api.inventory.getDriftHistory({
        gateway_identity: selectedGateway || undefined,
        limit: 50,
      }),
  });

  const {
    data: certificates = [],
    isLoading: isCertsLoading,
    refetch: refetchCerts,
  } = useQuery({
    queryKey: ["inventory-certificates", selectedGateway, certValidityFilter],
    queryFn: () =>
      api.inventory.listCertificates({
        gateway_identity: selectedGateway || undefined,
        validity_status: certValidityFilter || undefined,
        limit: 50,
      }),
  });

  // Mutations
  const importConfigMutation = useMutation({
    mutationFn: () => {
      if (!attestationConfirmed) {
        throw new Error("Operator attestation confirmation is required.");
      }
      if (!configText.trim()) {
        throw new Error("Configuration content cannot be empty. Please provide valid swanctl.conf syntax.");
      }
      return api.inventory.importConfiguration({
        gateway_identity: gatewayIdentity,
        authorized_scope: authorizedScope,
        source_type: sourceType,
        config_text: configText,
        collection_method: "OFFLINE_IMPORT",
        operator_id: operatorId,
        authorization_reference: authRef,
      });
    },
    onSuccess: (data) => {
      setFormMessage({
        type: "success",
        text: `Configuration snapshot imported successfully! ID: ${data.id} (Digest: ${data.canonical_digest.substring(0, 12)}…)`,
      });
      setConfigText("");
      queryClient.invalidateQueries({ queryKey: ["inventory-snapshots"] });
    },
    onError: (err: unknown) => {
      setFormMessage({
        type: "error",
        text: err instanceof Error ? err.message : "Failed to import configuration snapshot.",
      });
    },
  });

  const importCertMutation = useMutation({
    mutationFn: () => {
      if (!attestationConfirmed) {
        throw new Error("Operator attestation confirmation is required.");
      }
      return api.inventory.importCertificate({
        gateway_identity: gatewayIdentity,
        certificate_pem: certPemText,
        trust_store_pem: trustStorePemText || undefined,
        source_alias: sourceAlias,
        operator_id: operatorId,
        authorization_reference: authRef,
      });
    },
    onSuccess: (data) => {
      setFormMessage({
        type: "success",
        text: `Imported ${data.length} certificate(s) successfully!`,
      });
      setCertPemText("");
      setTrustStorePemText("");
      queryClient.invalidateQueries({ queryKey: ["inventory-certificates"] });
    },
    onError: (err: unknown) => {
      setFormMessage({
        type: "error",
        text: err instanceof Error ? err.message : "Failed to import certificate(s).",
      });
    },
  });

  const designateBaselineMutation = useMutation({
    mutationFn: (snapshotId: string) =>
      api.inventory.designateBaseline(snapshotId, {
        operator_id: operatorId,
        approval_reference: authRef,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["inventory-snapshots"] });
    },
  });

  const compareDriftMutation = useMutation({
    mutationFn: () => {
      if (!driftBaselineId || !driftObservedId) {
        throw new Error("Both baseline and observed snapshots must be selected.");
      }
      return api.inventory.compareDrift({
        baseline_snapshot_id: driftBaselineId,
        observed_snapshot_id: driftObservedId,
      });
    },
    onSuccess: (data) => {
      setSelectedDrift(data);
      queryClient.invalidateQueries({ queryKey: ["inventory-drift-history"] });
    },
    onError: (err: unknown) => {
      alert(`Drift comparison failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    },
  });

  // Calculate summary counters (exclude e3b0c442 empty hashes from verified baseline count)
  const totalSnapshots = snapshots.length;
  const baselineCount = snapshots.filter((s) => s.is_baseline && !s.canonical_digest?.startsWith("e3b0c442")).length;
  const totalCerts = certificates.length;
  const expiringSoonCerts = certificates.filter((c) => c.validity_status === "EXPIRING_SOON").length;
  const expiredCerts = certificates.filter((c) => c.validity_status === "EXPIRED").length;

  const driftStatusClass = (status: string) => {
    if (status === "MATCHED") return "bg-positive-bg text-positive border-positive-border";
    if (status === "DRIFT_DETECTED") return "bg-medium-bg text-medium border-medium-border";
    return "bg-info-bg text-info border-info-border";
  };

  const driftFieldClass = (status: string) => {
    if (status === "MATCHED") return "bg-positive-bg text-positive border-positive-border";
    if (status === "CHANGED") return "bg-medium-bg text-medium border-medium-border";
    if (status === "MISSING_IN_OBSERVED") return "bg-critical-bg text-critical border-critical-border";
    if (status === "NEW_IN_OBSERVED") return "bg-low-bg text-low border-low-border";
    return "bg-info-bg text-info border-info-border";
  };

  const certValidityClass = (status: string) => {
    if (status === "VALID") return "bg-positive-bg text-positive border-positive-border";
    if (status === "EXPIRING_SOON") return "bg-medium-bg text-medium border-medium-border";
    return "bg-critical-bg text-critical border-critical-border";
  };

  const chainClass = (status: string) => {
    if (status === "VALIDATED") return "bg-positive-bg text-positive border-positive-border";
    if (status === "FAILED") return "bg-critical-bg text-critical border-critical-border";
    return "bg-info-bg text-info border-info-border";
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="grid gap-4 border-b border-line pb-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
        <div className="min-w-0 space-y-1">
          <h1 className="text-xl font-semibold tracking-tight text-ink">
            Configuration & Certificate Inventory
          </h1>
          <p className="text-[13px] text-ink-2">
            Authoritative baseline tracking, semantic configuration drift detection, and public X.509 certificate intelligence.
          </p>
        </div>

        {/* Global Action / Refresh */}
        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              refetchSnapshots();
              refetchDrift();
              refetchCerts();
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setActiveTab("import")}
          >
            <PlusCircle className="w-3.5 h-3.5" />
            Import Snapshot / Cert
          </Button>
        </div>
      </div>

      {/* Configuration Intent vs Monitored Runtime Telemetry Clarification */}
      <div className="border border-line bg-panel-2 text-[13px] text-ink-2 flex items-start gap-2.5 p-3">
        <FileCode2 className="w-4 h-4 text-low shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-ink">Configured Intent Repository:</span> Parsed strongSwan (<code className="font-mono font-semibold">swanctl.conf</code>) files represent static administrative intent and authorized baselines. For active sensor health, heartbeat telemetry, and established IPsec tunnels, navigate to{" "}
          <Link href="/monitoring" className="text-accent-ink underline font-semibold">
            Live Monitoring
          </Link>
          .
        </div>
      </div>

      {/* Metrics Row */}
      <StatGrid className="sm:grid-cols-3 lg:grid-cols-5">
        <Stat label="Total Snapshots" value={totalSnapshots} hint="Recorded configurations" />
        <Stat label="Active Baselines" value={baselineCount} tone="positive" hint="Approved baselines" />
        <Stat label="Total Certificates" value={totalCerts} hint="Public X.509 credentials" />
        <Stat label="Expiring Soon" value={expiringSoonCerts} tone="medium" hint="< 30 days remaining" />
        <Stat
          label="Expired"
          value={expiredCerts}
          tone={expiredCerts > 0 ? "critical" : "default"}
          hint="Invalid validity end"
        />
      </StatGrid>

      {/* Epistemic Invariant Callout */}
      <div className="border border-line bg-panel-2 p-3 text-[13px] text-ink-2 flex items-start gap-2.5">
        <ShieldCheck className="w-4 h-4 text-positive shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-ink">Epistemic Truth Guard:</span> Parsed configuration is evidence of <span className="font-mono text-low">CONFIGURED INTENT</span>. Active runtime status is <span className="font-mono text-positive">RUNTIME EVIDENCE</span>. All secrets (PSKs, private keys, passwords) are scrubbed and replaced with <span className="font-mono text-medium">[REDACTED_SECRET]</span> prior to storage. Private keys are strictly rejected at ingestion.
        </div>
      </div>

      {/* Tabs Header */}
      <Tabs
        active={activeTab}
        onChange={(id) => setActiveTab(id as typeof activeTab)}
        items={[
          { id: "snapshots", label: "Snapshots & Baselines", count: snapshots.length },
          { id: "drift", label: "Configuration Drift", count: driftHistory.length },
          { id: "certificates", label: "Certificate Inventory", count: certificates.length },
          { id: "import", label: "Import Ingestion" },
        ]}
      />

      {/* TAB 1: SNAPSHOTS & BASELINES */}
      {activeTab === "snapshots" && (
        <Section index="§1" title="Configuration Snapshots & Baselines">
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <label htmlFor="snapshot-gateway-filter" className="text-[13px] text-ink-3 whitespace-nowrap">Filter gateway:</label>
                <Input
                  id="snapshot-gateway-filter"
                  type="text"
                  placeholder="All gateways…"
                  value={selectedGateway}
                  onChange={(e) => setSelectedGateway(e.target.value)}
                  className="w-48"
                />
              </div>
              <div className="text-ink-3 text-[13px]">
                Showing {snapshots.length} snapshot(s)
              </div>
            </div>

            {isSnapshotsLoading ? (
              <div className="flex min-h-64 flex-col items-center justify-center border-y border-line px-4 py-10 text-center"><Loader2 className="h-6 w-6 animate-spin text-brand" /><h3 className="mt-4 font-sans text-xl font-extrabold">Loading configuration snapshots…</h3><p className="mt-1 text-sm text-ink-3">Checking the selected gateway inventory.</p></div>
            ) : snapshots.length === 0 ? (
              <div className="flex min-h-64 flex-col items-center justify-center border-y border-line px-5 py-10 text-center">
                <div className="grid h-12 w-12 place-items-center border-2 border-ink bg-accent"><FileCode2 className="h-5 w-5" /></div>
                <h3 className="mt-4 font-sans text-2xl font-extrabold">No configuration snapshots yet</h3>
                <p className="mt-2 max-w-[48ch] text-sm leading-6 text-ink-2">Import an authorized strongSwan swanctl.conf file to record configured intent and establish a baseline.</p>
                <Button variant="primary" size="md" onClick={() => setActiveTab("import")} className="mt-5"><PlusCircle className="w-4 h-4" />Import a configuration</Button>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Gateway Identity</TableHead>
                    <TableHead>Status / Baseline</TableHead>
                    <TableHead>Source Type</TableHead>
                    <TableHead>Digest (SHA-256)</TableHead>
                    <TableHead>Connections</TableHead>
                    <TableHead>Created At (UTC)</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {snapshots.map((s) => {
                    const conns = s.normalized_ir?.connections || {};
                    const connCount = Object.keys(conns).length;
                    return (
                      <TableRow key={s.id}>
                        <TableCell mono className="font-semibold text-ink">
                          {s.gateway_identity}
                          <div className="text-[11px] text-ink-3 font-normal">
                            Scope: {s.authorized_scope}
                          </div>
                        </TableCell>

                        <TableCell>
                          {s.canonical_digest?.startsWith("e3b0c442") ? (
                            <span
                              className="inline-flex items-center gap-1 bg-medium-bg text-medium border border-medium-border px-2 py-0.5 text-[11px] font-mono font-semibold"
                              title="SHA-256 digest of empty content (e3b0c442). Not an approved configuration baseline."
                            >
                              <AlertTriangle className="w-3 h-3" />
                              Unverified / Empty Baseline
                            </span>
                          ) : s.is_baseline ? (
                            <span className="inline-flex items-center gap-1 bg-positive-bg text-positive border border-positive-border px-2 py-0.5 text-[11px] font-mono font-semibold">
                              <CheckCircle2 className="w-3 h-3" />
                              Baseline v{s.baseline_version || 1}
                            </span>
                          ) : (
                            <span className="inline-flex items-center bg-info-bg text-info border border-info-border px-2 py-0.5 text-[11px] font-mono">
                              Snapshot
                            </span>
                          )}
                        </TableCell>

                        <TableCell mono>
                          <span className="text-low bg-low-bg px-1.5 py-0.5 text-[11px] border border-low-border">
                            {s.source_type}
                          </span>
                        </TableCell>

                        <TableCell mono>
                          <CopyableValue value={s.canonical_digest} truncate={true} />
                          {s.canonical_digest?.startsWith("e3b0c442") && (
                            <div className="text-[11px] text-medium font-mono mt-0.5">
                              (empty content digest)
                            </div>
                          )}
                        </TableCell>

                        <TableCell mono className="text-ink-2">
                          {connCount} connection(s)
                          {s.unsupported_directives?.length > 0 && (
                            <span className="ml-1 text-[11px] text-medium">
                              ({s.unsupported_directives.length} unmodeled)
                            </span>
                          )}
                        </TableCell>

                        <TableCell mono className="text-ink-3">
                          {new Date(s.created_at).toLocaleString()}
                        </TableCell>

                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => setSelectedSnapshot(s)}
                            >
                              <Eye className="w-3 h-3" />
                              View IR
                            </Button>

                            {!s.is_baseline && (
                              <Button
                                variant="primary"
                                size="sm"
                                onClick={() => designateBaselineMutation.mutate(s.id)}
                                disabled={designateBaselineMutation.isPending}
                                title="Promote to authoritative baseline"
                              >
                                Set Baseline
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </div>
        </Section>
      )}
      {/* TAB 2: CONFIGURATION DRIFT */}
      {activeTab === "drift" && (
        <Section index="§2" title="Configuration Drift">
          <div className="space-y-4">
            {/* Drift Compare Launcher */}
            <div className="border border-line bg-panel-2 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-ink flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-low" />
                Compare Snapshots for Semantic Configuration Drift
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Field label="Baseline Snapshot">
                  <Select
                    value={driftBaselineId}
                    onChange={(e) => setDriftBaselineId(e.target.value)}
                  >
                    <option value="">Select baseline…</option>
                    {snapshots.map((s) => {
                      const isEmptyDigest = s.canonical_digest?.startsWith("e3b0c442");
                      return (
                        <option key={s.id} value={s.id} disabled={isEmptyDigest}>
                          {isEmptyDigest
                            ? "[unverified / empty baseline] "
                            : s.is_baseline
                            ? "[baseline] "
                            : ""}
                          {s.gateway_identity} ({new Date(s.created_at).toLocaleDateString()}) - {s.canonical_digest.substring(0, 8)}
                        </option>
                      );
                    })}
                  </Select>
                </Field>

                <Field label="Observed Snapshot">
                  <Select
                    value={driftObservedId}
                    onChange={(e) => setDriftObservedId(e.target.value)}
                  >
                    <option value="">Select observed…</option>
                    {snapshots.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.gateway_identity} ({new Date(s.created_at).toLocaleDateString()}) - {s.canonical_digest.substring(0, 8)}
                      </option>
                    ))}
                  </Select>
                </Field>

                <div className="flex items-end">
                  <Button
                    variant="primary"
                    onClick={() => compareDriftMutation.mutate()}
                    disabled={!driftBaselineId || !driftObservedId || compareDriftMutation.isPending}
                    className="w-full"
                  >
                    {compareDriftMutation.isPending ? "Comparing…" : "Evaluate Configuration Drift"}
                  </Button>
                </div>
              </div>
            </div>

            {/* Active Drift Comparison View */}
            {selectedDrift && (
              <div className="border border-low-border bg-panel p-4 space-y-3">
                <div className="flex items-center justify-between gap-3 border-b border-line pb-3">
                  <div>
                    <h4 className="text-sm font-semibold text-ink flex items-center gap-2">
                      <span>Drift Report: {selectedDrift.gateway_identity}</span>
                      <span className={`text-[11px] px-2 py-0.5 border font-semibold uppercase ${driftStatusClass(selectedDrift.comparison_status)}`}>
                        {selectedDrift.comparison_status}
                      </span>
                    </h4>
                    <div className="text-xs text-ink-3 font-mono mt-0.5">
                      Evaluated at {new Date(selectedDrift.created_at).toLocaleString()}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 font-mono text-xs">
                    <span className="text-positive">Matched: {selectedDrift.drift_summary.matched_count}</span>
                    <span className="text-medium">Changed: {selectedDrift.drift_summary.changed_count}</span>
                    <span className="text-critical">Missing: {selectedDrift.drift_summary.missing_count}</span>
                    <span className="text-low">New: {selectedDrift.drift_summary.new_count}</span>
                    <Button variant="ghost" size="sm" onClick={() => setSelectedDrift(null)}>
                      Close
                    </Button>
                  </div>
                </div>

                {/* Field Drift Table */}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Field Path</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Baseline Value</TableHead>
                      <TableHead>Observed Value</TableHead>
                      <TableHead>Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedDrift.field_drifts.map((fd, i) => (
                      <TableRow key={i}>
                        <TableCell mono className="font-semibold text-ink">{fd.field_path}</TableCell>
                        <TableCell>
                          <span className={`px-1.5 py-0.5 border text-[11px] font-semibold ${driftFieldClass(fd.status)}`}>
                            {fd.status}
                          </span>
                        </TableCell>
                        <TableCell className="text-ink-2">
                          {fd.baseline_value !== null ? String(fd.baseline_value) : <span className="text-ink-3">None</span>}
                        </TableCell>
                        <TableCell className="text-ink-2">
                          {fd.observed_value !== null ? String(fd.observed_value) : <span className="text-ink-3">None</span>}
                        </TableCell>
                        <TableCell className="text-ink-3">{fd.description}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            {/* Drift History Table */}
            <div>
              <Subsection title="Drift Evaluation History">
                {isDriftLoading ? (
                  <EmptyState compact title="Loading drift records…" />
                ) : driftHistory.length === 0 ? (
                  <EmptyState
                    icon={<GitCompare />}
                    title="No drift records recorded yet"
                    description="Compare two snapshots above."
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Gateway</TableHead>
                        <TableHead>Comparison Status</TableHead>
                        <TableHead>Drift Breakdown</TableHead>
                        <TableHead>Evaluated At</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {driftHistory.map((d) => (
                        <TableRow key={d.id}>
                          <TableCell mono className="font-semibold text-ink">
                            {d.gateway_identity}
                          </TableCell>
                          <TableCell>
                            <span className={`text-[11px] font-mono px-2 py-0.5 border font-semibold uppercase ${driftStatusClass(d.comparison_status)}`}>
                              {d.comparison_status}
                            </span>
                          </TableCell>
                          <TableCell mono className="text-ink-3">
                            {d.drift_summary.changed_count} changed, {d.drift_summary.missing_count} missing, {d.drift_summary.new_count} new ({d.drift_summary.matched_count} matched)
                          </TableCell>
                          <TableCell mono className="text-ink-3">
                            {new Date(d.created_at).toLocaleString()}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => setSelectedDrift(d)}
                            >
                              View Diff
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </Subsection>
            </div>
          </div>
        </Section>
      )}

      {/* TAB 3: CERTIFICATE INVENTORY */}
      {activeTab === "certificates" && (
        <Section index="§3" title="Certificate Inventory">
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <label htmlFor="cert-validity-filter" className="text-[13px] text-ink-3">Validity status:</label>
                <Select
                  id="cert-validity-filter"
                  value={certValidityFilter}
                  onChange={(e) => setCertValidityFilter(e.target.value)}
                  className="w-44"
                >
                  <option value="">All Statuses</option>
                  <option value="VALID">VALID</option>
                  <option value="EXPIRING_SOON">EXPIRING_SOON</option>
                  <option value="EXPIRED">EXPIRED</option>
                  <option value="NOT_YET_VALID">NOT_YET_VALID</option>
                </Select>
              </div>
              <div className="text-ink-3 text-[13px]">
                Showing {certificates.length} certificate(s)
              </div>
            </div>

            {isCertsLoading ? (
              <EmptyState compact title="Loading certificate inventory…" />
            ) : certificates.length === 0 ? (
              <EmptyState
                icon={<FileKey2 />}
                title="No certificates recorded"
                description="Import an X.509 PEM certificate to begin."
                action={
                  <Button variant="primary" size="sm" onClick={() => setActiveTab("import")}>
                    <PlusCircle className="w-3.5 h-3.5" />
                    Import Certificate
                  </Button>
                }
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Subject DN / Fingerprint</TableHead>
                    <TableHead>Validity Status</TableHead>
                    <TableHead>Days Remaining</TableHead>
                    <TableHead>Key & Signature</TableHead>
                    <TableHead>strongSwan Connection</TableHead>
                    <TableHead>Chain Validation</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {certificates.map((cert) => {
                    const isDemoSeedCert =
                      cert.id?.replace(/-/g, "").toLowerCase() === "7a2dc9ca442f4ce49b358a0acb4758e0" ||
                      cert.subject_dn?.includes("CN=vpn-gw-alpha.corp.internal");
                    return (
                      <TableRow key={cert.id}>
                        <TableCell mono className="font-semibold text-ink max-w-xs">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="truncate" title={cert.subject_dn}>{cert.subject_dn}</span>
                            {isDemoSeedCert && (
                              <span
                                className="inline-flex items-center px-1.5 py-0.5 border text-[11px] font-mono font-semibold bg-medium-bg text-medium border-medium-border"
                                title="Seeded test fixture for demonstration purposes"
                              >
                                [demo / seed data]
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-ink-3 font-normal">
                            SHA-256: {cert.sha256_fingerprint.substring(0, 16)}…
                          </div>
                        </TableCell>

                        <TableCell>
                          <span className={`text-[11px] font-mono px-2 py-0.5 border font-semibold uppercase ${certValidityClass(cert.validity_status)}`}>
                            {cert.validity_status}
                          </span>
                        </TableCell>

                        <TableCell mono>
                          <span
                            className={
                              cert.days_until_expiry < 0
                                ? "text-critical font-semibold"
                                : cert.days_until_expiry <= 30
                                ? "text-medium font-semibold"
                                : "text-ink-2"
                            }
                          >
                            {cert.days_until_expiry < 0
                              ? `Expired ${Math.abs(cert.days_until_expiry)}d ago`
                              : `${cert.days_until_expiry} days`}
                          </span>
                        </TableCell>

                        <TableCell mono className="text-ink-2">
                          {cert.public_key_algorithm} ({cert.public_key_bits} bits)
                          <div className="text-[11px] text-ink-3">{cert.signature_algorithm}</div>
                        </TableCell>

                        <TableCell mono>
                          {cert.associated_connection ? (
                            <span className="text-positive bg-positive-bg px-1.5 py-0.5 border border-positive-border text-[11px]">
                              {cert.associated_connection}
                            </span>
                          ) : (
                            <span className="text-ink-3 text-[11px]">{cert.identity_association_status}</span>
                          )}
                        </TableCell>

                        <TableCell mono>
                          <span className={`text-[11px] px-1.5 py-0.5 border ${chainClass(cert.chain_validation_status)}`}>
                            {cert.chain_validation_status}
                          </span>
                        </TableCell>

                        <TableCell className="text-right">
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => setSelectedCert(cert)}
                          >
                            Inspect
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </div>
        </Section>
      )}

      {/* TAB 4: IMPORT INGESTION WORKBENCH */}
      {activeTab === "import" && (
        <Section index="§4" title="Import Ingestion">
          <div className="space-y-4 max-w-4xl">
            <div className="flex items-center gap-4 border-b border-line pb-3">
              <span className="text-ink-2 font-semibold">Import target:</span>
              <label className="flex items-center gap-1.5 text-ink-2 cursor-pointer">
                <input
                  type="radio"
                  name="importType"
                  checked={importType === "config"}
                  onChange={() => setImportType("config")}
                />
                strongSwan Configuration (swanctl.conf)
              </label>
              <label className="flex items-center gap-1.5 text-ink-2 cursor-pointer">
                <input
                  type="radio"
                  name="importType"
                  checked={importType === "cert"}
                  onChange={() => setImportType("cert")}
                />
                X.509 Public Certificate (PEM)
              </label>
            </div>

            {/* Scope & Operator Details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Field label="Gateway Identity (FQDN / ID)">
                <Input
                  type="text"
                  value={gatewayIdentity}
                  onChange={(e) => setGatewayIdentity(e.target.value)}
                  mono
                />
              </Field>

              <Field label="Authorized Scope (CIDR)">
                <Input
                  type="text"
                  value={authorizedScope}
                  onChange={(e) => setAuthorizedScope(e.target.value)}
                  mono
                />
              </Field>

              <Field label="Operator ID">
                <Input
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                />
              </Field>

              <Field label="Authorization Reference">
                <Input
                  type="text"
                  value={authRef}
                  onChange={(e) => setAuthRef(e.target.value)}
                />
              </Field>
            </div>

            {/* Config Import Form */}
            {importType === "config" && (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-ink-2 font-semibold">
                    swanctl.conf Text Payload (max 1MB, parsed safely in-memory):
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setConfigText(`connections {
    gw-prod-tunnel {
        version = 2
        local_addrs = 192.0.2.1
        remote_addrs = 198.51.100.1
        proposals = aes256gcm16-prfsha256-ecp256
        encap = yes
        local {
            auth = pubkey
            certs = gw-prod.crt
            id = gw-prod.agency.gov
        }
        remote {
            auth = pubkey
            id = peer.partner.gov
        }
        children {
            net-prod {
                mode = tunnel
                local_ts = 10.10.0.0/16
                remote_ts = 10.20.0.0/16
                esp_proposals = aes256gcm16-ecp256
                start_action = start
            }
        }
    }
}
secrets {
    rsa-priv {
        file = /etc/swanctl/private/priv.key
        secret = "secret-production-token-1234"
    }
}`);
                    }}
                  >
                    Load Sample swanctl.conf
                  </Button>
                </div>
                <Textarea
                  rows={10}
                  value={configText}
                  onChange={(e) => setConfigText(e.target.value)}
                  placeholder="Paste strongSwan swanctl.conf content here…"
                  mono
                />
              </div>
            )}

            {/* Certificate Import Form */}
            {importType === "cert" && (
              <div className="space-y-3">
                <Field label="Public X.509 Certificate (PEM Format)">
                  <Textarea
                    rows={6}
                    value={certPemText}
                    onChange={(e) => setCertPemText(e.target.value)}
                    placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                    mono
                  />
                </Field>

                <Field label="Optional CA Trust Store (PEM Format) for Chain Validation">
                  <Textarea
                    rows={4}
                    value={trustStorePemText}
                    onChange={(e) => setTrustStorePemText(e.target.value)}
                    placeholder="Optional root CA certificates for chain evaluation…"
                    mono
                  />
                </Field>
              </div>
            )}

            {/* Private Key Safety Notice */}
            <div className="border border-medium-border bg-medium-bg p-3 text-[13px] text-medium flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <strong>Security Boundary Notice:</strong> Never upload private keys. The parser enforces an active rejection boundary against private key headers. Any secrets in <code>swanctl.conf</code> are automatically redacted and never persisted or logged.
              </div>
            </div>

            {/* Operator Attestation */}
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={attestationConfirmed}
                onChange={(e) => setAttestationConfirmed(e.target.checked)}
                className="accent-accent"
              />
              <span className="text-ink-2 text-[13px]">
                I attest that this configuration/certificate artifact belongs to authorized gateway <code>{gatewayIdentity}</code> within scope <code>{authorizedScope}</code>.
              </span>
            </label>

            {formMessage && (
              <div
                role="status"
                className={`p-3 text-xs border ${
                  formMessage.type === "success"
                    ? "bg-positive-bg text-positive border-positive-border"
                    : "bg-critical-bg text-critical border-critical-border"
                }`}
              >
                {formMessage.text}
              </div>
            )}

            <Button
              variant="primary"
              onClick={() => {
                setFormMessage(null);
                if (importType === "config") {
                  importConfigMutation.mutate();
                } else {
                  importCertMutation.mutate();
                }
              }}
              disabled={
                !attestationConfirmed ||
                (importType === "config" && !configText.trim()) ||
                (importType === "cert" && !certPemText.trim()) ||
                importConfigMutation.isPending ||
                importCertMutation.isPending
              }
            >
              {importConfigMutation.isPending || importCertMutation.isPending
                ? "Ingesting…"
                : importType === "config"
                ? "Ingest & Normalize Configuration"
                : "Ingest & Validate Certificate"}
            </Button>
          </div>
        </Section>
      )}

      {/* INSPECTOR DRAWER: SNAPSHOT IR */}
      {selectedSnapshot && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedSnapshot(null)}
          title={`Snapshot IR: ${selectedSnapshot.gateway_identity}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="border border-line bg-panel-2 p-3 space-y-1">
              <div><strong className="text-ink-3">Snapshot ID:</strong> {selectedSnapshot.id}</div>
              <div><strong className="text-ink-3">Canonical SHA-256:</strong> {selectedSnapshot.canonical_digest}</div>
              <div><strong className="text-ink-3">Baseline State:</strong> {selectedSnapshot.is_baseline ? `Authoritative Baseline v${selectedSnapshot.baseline_version}` : "Observed Snapshot"}</div>
              <div><strong className="text-ink-3">Parser Version:</strong> {selectedSnapshot.parser_version}</div>
              <div><strong className="text-ink-3">Source Type:</strong> {selectedSnapshot.source_type}</div>
              <div><strong className="text-ink-3">Approved By:</strong> {selectedSnapshot.approved_by || "None"} ({selectedSnapshot.approval_reference || "N/A"})</div>
            </div>

            {selectedSnapshot.unsupported_directives?.length > 0 && (
              <div>
                <h4 className="font-semibold text-medium mb-1">Unsupported / Unmodeled Directives:</h4>
                <div className="border border-medium-border bg-panel-2 p-2 max-h-40 overflow-y-auto">
                  {selectedSnapshot.unsupported_directives.map((u, i) => (
                    <div key={i} className="text-ink-2">
                      <code>{u.path}</code>: {String(u.value)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              <h4 className="font-semibold text-ink-2 mb-1">Normalized Configuration IR (Public Fields):</h4>
              <pre className="border border-line bg-panel-3 text-ink-2 overflow-x-auto text-[11px] max-h-96 p-3">
                {JSON.stringify(selectedSnapshot.normalized_ir, null, 2)}
              </pre>
            </div>

            {/* SOC Analyst Workflow Transitions */}
            <div className="pt-2 border-t border-line space-y-1.5">
              <span className="text-[11px] text-ink-3 uppercase font-semibold block">
                SOC Analyst Workflow Transitions
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <ButtonLink
                  href={`/monitoring?tab=fleet&gateway=${encodeURIComponent(selectedSnapshot.gateway_identity)}`}
                  variant="secondary"
                  size="sm"
                >
                  <Radio className="w-3.5 h-3.5 text-accent" />
                  <span>Telemetry</span>
                </ButtonLink>
                <ButtonLink
                  href={`/monitoring?tab=timeline&gateway=${encodeURIComponent(selectedSnapshot.gateway_identity)}`}
                  variant="secondary"
                  size="sm"
                >
                  <Layers className="w-3.5 h-3.5 text-low" />
                  <span>Events</span>
                </ButtonLink>
                <ButtonLink
                  href="/analyses"
                  variant="secondary"
                  size="sm"
                >
                  <Activity className="w-3.5 h-3.5 text-positive" />
                  <span>Analyses</span>
                </ButtonLink>
              </div>
            </div>
          </div>
        </InspectorDrawer>
      )}

      {/* INSPECTOR DRAWER: CERTIFICATE DETAILS */}
      {selectedCert && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedCert(null)}
          title={`Certificate: ${selectedCert.subject_dn}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="border border-line bg-panel-2 p-3 space-y-1">
              {(selectedCert.id?.replace(/-/g, "").toLowerCase() === "7a2dc9ca442f4ce49b358a0acb4758e0" ||
                selectedCert.subject_dn?.includes("CN=vpn-gw-alpha.corp.internal")) && (
                <div className="mb-2">
                  <span className="inline-flex items-center px-2 py-0.5 border text-[11px] font-mono font-semibold bg-medium-bg text-medium border-medium-border">
                    [demo / seed data]
                  </span>
                </div>
              )}
              <div><strong className="text-ink-3">Fingerprint (SHA-256):</strong> {selectedCert.sha256_fingerprint}</div>
              <div><strong className="text-ink-3">Serial Number:</strong> {selectedCert.serial_number}</div>
              <div><strong className="text-ink-3">Validity:</strong> <StateText value={selectedCert.validity_status} /> ({selectedCert.days_until_expiry} days remaining)</div>
              <div><strong className="text-ink-3">Valid Window:</strong> {new Date(selectedCert.not_valid_before).toUTCString()} to {new Date(selectedCert.not_valid_after).toUTCString()}</div>
              <div><strong className="text-ink-3">Key Info:</strong> {selectedCert.public_key_algorithm} {selectedCert.public_key_bits} bits</div>
              <div><strong className="text-ink-3">Signature Alg:</strong> {selectedCert.signature_algorithm}</div>
              <div><strong className="text-ink-3">Is CA:</strong> {selectedCert.is_ca ? "YES" : "NO"}</div>
              <div><strong className="text-ink-3">Connection Mapping:</strong> {selectedCert.associated_connection || "Unassociated"} ({selectedCert.identity_association_status})</div>
              <div><strong className="text-ink-3">Chain Validation:</strong> <StateText value={selectedCert.chain_validation_status} /></div>
              <div><strong className="text-ink-3">Revocation Status:</strong> <StateText value={selectedCert.revocation_status} /></div>
            </div>

            {selectedCert.subject_alt_names && Object.keys(selectedCert.subject_alt_names).length > 0 && (
              <div>
                <h4 className="font-semibold text-ink-2 mb-1">Subject Alternative Names (SANs):</h4>
                <div className="border border-line bg-panel-2 p-3 space-y-1">
                  {Object.entries(selectedCert.subject_alt_names).map(([type, values]) => (
                    <div key={type} className="text-ink-2">
                      <strong className="text-ink-3 uppercase text-[11px]">{type}:</strong> {values.join(", ")}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              <h4 className="font-semibold text-ink-2 mb-1">Issuer DN:</h4>
              <div className="border border-line bg-panel-2 p-2 text-ink-3 break-all">
                {selectedCert.issuer_dn}
              </div>
            </div>
          </div>
        </InspectorDrawer>
      )}
    </div>
  );
}

export default function InventoryPage() {
  return (
    <Suspense
      fallback={
        <EmptyState compact title="Loading Configuration & Certificate Inventory catalog…" />
      }
    >
      <InventoryContent />
    </Suspense>
  );
}
