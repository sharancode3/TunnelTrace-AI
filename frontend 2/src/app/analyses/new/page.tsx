"use client";

import React, { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { SampleCaptureDTO } from "@/lib/api/types";
import {
  UploadCloud,
  FileCode,
  AlertTriangle,
  Play,
  Square,
  ArrowRight,
  Terminal,
  Copy,
  Check,
  Info,
  Shield,
  ChevronDown,
} from "lucide-react";

type Tab = "upload" | "samples" | "live";

export default function NewAnalysisPage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [activeTab, setActiveTab] = useState<Tab>("upload");

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [showCaptureHelp, setShowCaptureHelp] = useState(false);

  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [captureDuration, setCaptureDuration] = useState<number>(30);
  const [liveSessionId, setLiveSessionId] = useState<string | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);

  const { data: samples, isLoading: isSamplesLoading, isError: isSamplesError, refetch: refetchSamples } = useQuery({
    queryKey: ["capture-samples"],
    queryFn: () => api.captures.getSamples(),
  });

  const { data: interfaces, isLoading: isInterfacesLoading, isError: isInterfacesError, refetch: refetchInterfaces } = useQuery({
    queryKey: ["live-interfaces"],
    queryFn: () => api.captures.listInterfaces(),
    enabled: activeTab === "live",
  });

  const [duplicateNotice, setDuplicateNotice] = useState<{
    captureId: string;
    existingAnalysisId: string;
    pipelineVersion: string;
    source: "upload" | "sample";
  } | null>(null);

  const [ingestingSampleId, setIngestingSampleId] = useState<string | null>(null);
  const ingestSampleMutation = useMutation({
    mutationFn: async ({
      sampleId,
      forceRerun,
    }: {
      sampleId: string;
      forceRerun?: boolean;
    }) => {
      setIngestingSampleId(sampleId);
      setUploadError(null);
      setDuplicateNotice(null);
      const capture = await api.captures.ingestSample(sampleId);
      if (capture.already_analyzed && capture.existing_analysis_id && !forceRerun) {
        setIngestingSampleId(null);
        setDuplicateNotice({
          captureId: sampleId,
          existingAnalysisId: capture.existing_analysis_id,
          pipelineVersion: capture.existing_pipeline_version || "2.0.0",
          source: "sample",
        });
        return { analysis: null };
      }
      const analysis = await api.analyses.create(capture.capture_id, forceRerun);
      return { analysis };
    },
    onSuccess: (data) => {
      if (data.analysis) {
        router.push(`/analyses/${data.analysis.analysis_id}/overview`);
      }
    },
    onError: (err: any) => {
      setIngestingSampleId(null);
      setUploadError(err.message || "Failed to ingest sample capture fixture");
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async ({ file, forceRerun }: { file: File; forceRerun?: boolean }) => {
      setUploadError(null);
      setDuplicateNotice(null);
      const capture = await api.captures.upload(file, forceRerun);

      if (capture.already_analyzed && capture.existing_analysis_id && !forceRerun) {
        setDuplicateNotice({
          captureId: capture.capture_id,
          existingAnalysisId: capture.existing_analysis_id,
          pipelineVersion: capture.existing_pipeline_version || "2.0.0",
          source: "upload",
        });
        return { capture, analysis: null };
      }

      const analysis = await api.analyses.create(capture.capture_id, forceRerun);
      return { capture, analysis };
    },
    onSuccess: (data) => {
      if (data.analysis) {
        router.push(`/analyses/${data.analysis.analysis_id}/overview`);
      }
    },
    onError: (err: any) => {
      if (err?.status === 405) {
        setUploadError(
          "HTTP 405 Method Not Allowed: The multipart ingestion endpoint is misconfigured on the server. Ensure backend mounts POST /api/v1/captures."
        );
      } else {
        setUploadError(err.message || "Failed to upload and initiate analysis");
      }
    },
  });

  const handleFileSelect = (file: File) => {
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "pcap" && ext !== "pcapng") {
      setUploadError(
        "Invalid file type. Supported formats: standard libpcap (.pcap) and pcapng (.pcapng)."
      );
      return;
    }
    const maxBytes = 250 * 1024 * 1024;
    if (file.size > maxBytes) {
      setUploadError(
        `File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds configured limit of 250 MB.`
      );
      return;
    }
    setSelectedFile(file);
    setUploadError(null);
    setDuplicateNotice(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleStartUpload = () => {
    if (!selectedFile) return;
    uploadMutation.mutate({ file: selectedFile, forceRerun: false });
  };

  const handleStartLiveCapture = async () => {
    if (!selectedInterface) {
      setLiveError("Please select an authorized network interface.");
      return;
    }
    setLiveError(null);
    try {
      const res = await api.captures.startLive({
        interface_id: selectedInterface,
        duration_sec: captureDuration,
      });
      setLiveSessionId(res.session_id);
    } catch (err: any) {
      setLiveError(err.message || "Failed to start live capture.");
    }
  };

  const handleStopLiveCapture = async () => {
    if (!liveSessionId) return;
    try {
      const res = await api.captures.stopLive(liveSessionId);
      if (res.capture_id) {
        const analysis = await api.analyses.create(res.capture_id);
        router.push(`/analyses/${analysis.analysis_id}/overview`);
      }
    } catch (err: any) {
      setLiveError(err.message || "Failed to stop live capture session.");
    }
  };

  const handleCopy = (text: string, key: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedCommand(key);
      setTimeout(() => setCopiedCommand(null), 2500);
    }
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: "upload", label: "Upload capture" },
    { id: "samples", label: "Sample captures" },
    { id: "live", label: "Live capture" },
  ];

  return (
    <div className="max-w-3xl mx-auto space-y-5">
      <div className="space-y-1">
        <h1 className="text-xl font-semibold text-ink tracking-tight">
          New Analysis
        </h1>
        <p className="text-[13px] text-ink-2">
          Ingest a packet capture to reconstruct the tunnel, assess its
          cryptographic posture, and produce verifiable evidence.
        </p>
      </div>

      {/* Tabs */}
      <div role="tablist" className="flex items-center gap-1 border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={activeTab === t.id}
            onClick={() => setActiveTab(t.id)}
            className={`-mb-px px-3 h-9 text-[13px] font-medium border-b-2 transition-colors ${
              activeTab === t.id
                ? "border-accent text-ink"
                : "border-transparent text-ink-3 hover:text-ink hover:border-line-strong"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === "upload" && (
        <div className="space-y-4">
          <Card title="Upload a capture" padded={false}>
            <div className="p-4 space-y-4">
              <div
                onDrop={handleDrop}
                onDragOver={(e) => e.preventDefault()}
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    fileInputRef.current?.click();
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label="Select a capture file"
                className={`border border-dashed p-10 sm:p-14 text-center cursor-pointer transition-colors ${
                  selectedFile
                    ? "border-accent bg-accent-soft"
                    : "border-line-strong hover:border-ink-3 bg-panel-2"
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pcap,.pcapng"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleFileSelect(e.target.files[0]);
                    }
                  }}
                />
                <div className="space-y-4">
                  <div className="w-14 h-14 mx-auto bg-panel-3 border border-line flex items-center justify-center">
                    <UploadCloud className="w-7 h-7 text-accent" />
                  </div>
                  <div>
                    <p className="text-2xl font-semibold text-ink leading-tight break-all">
                      {selectedFile
                        ? selectedFile.name
                        : "Select a file or drag it here"}
                    </p>
                    <p className="text-xs font-mono text-ink-3 mt-3 pt-3 border-t border-line">
                      .pcap or .pcapng · validated server-side · 250 MB limit
                    </p>
                  </div>
                </div>
                {selectedFile && (
                  <div className="mt-3 inline-flex items-center gap-2 px-2.5 py-1 bg-panel border border-line text-xs font-mono text-ink-2">
                    <FileCode className="w-3.5 h-3.5 text-ink-3" />
                    <span>{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</span>
                    <span className="text-positive font-medium">Ready</span>
                  </div>
                )}
              </div>

              {uploadError && (
                <div role="alert" className="p-3 bg-critical-bg border border-critical-border text-critical text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{uploadError}</span>
                </div>
              )}

              {duplicateNotice && duplicateNotice.source === "upload" && (
                <div className="p-3 bg-medium-bg border border-medium-border text-xs space-y-2.5">
                  <div className="flex items-center gap-2 text-medium font-medium">
                    <Info className="w-4 h-4 shrink-0" />
                    <span>This capture was already analyzed</span>
                  </div>
                  <p className="text-ink-2">
                    Identical capture analyzed under pipeline v
                    {duplicateNotice.pipelineVersion}. Open the existing run or
                    force a fresh re-run.
                  </p>
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() =>
                        router.push(
                          `/analyses/${duplicateNotice.existingAnalysisId}/overview`
                        )
                      }
                    >
                      Open existing
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        if (selectedFile) {
                          uploadMutation.mutate({
                            file: selectedFile,
                            forceRerun: true,
                          });
                        }
                      }}
                    >
                      Force re-run
                    </Button>
                  </div>
                </div>
              )}

              {uploadMutation.isPending && (
                <div className="flex items-center gap-3 border-y border-line py-3 text-xs text-ink-2" role="status" aria-live="polite">
                  <span className="h-1.5 w-10 shrink-0 animate-pulse bg-accent-press" aria-hidden="true" />
                  <span>Sending the capture and starting its analysis…</span>
                </div>
              )}

              <div className="flex items-center justify-end pt-1">
                <Button
                  variant="primary"
                  disabled={!selectedFile || uploadMutation.isPending}
                  onClick={handleStartUpload}
                >
                  {uploadMutation.isPending ? "Processing…" : "Start analysis"}
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </Card>

          {/* Progressive disclosure: capture from your network */}
          <div className="border border-line bg-panel">
            <button
              type="button"
              onClick={() => setShowCaptureHelp((s) => !s)}
              aria-expanded={showCaptureHelp}
              className="flex items-center justify-between w-full px-4 py-2.5 text-[13px] font-medium text-ink-2 hover:text-ink transition-colors"
            >
              <span className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-ink-3" />
                Capture from your network
              </span>
              <ChevronDown
                className={`w-4 h-4 text-ink-3 transition-transform ${
                  showCaptureHelp ? "rotate-180" : ""
                }`}
              />
            </button>
            {showCaptureHelp && (
              <div className="px-4 pb-4 space-y-3 text-xs text-ink-2">
                <p>
                  Capture IPsec traffic with the BPF filter{" "}
                  <code className="font-mono text-[11px] bg-panel-2 px-1 py-0.5">
                    udp port 500 or udp port 4500 or esp
                  </code>
                  , then upload the file above.
                </p>
                <CodeBlock
                  label="Linux / macOS"
                  command='sudo tshark -i eth0 -f "udp port 500 or udp port 4500 or esp" -w ipsec_capture.pcapng'
                  copied={copiedCommand === "linux"}
                  onCopy={() =>
                    handleCopy(
                      'sudo tshark -i eth0 -f "udp port 500 or udp port 4500 or esp" -w ipsec_capture.pcapng',
                      "linux"
                    )
                  }
                />
                <CodeBlock
                  label="Windows"
                  command='& "C:\Program Files\Wireshark\tshark.exe" -i 1 -f "udp port 500 or udp port 4500 or esp" -w ipsec_capture.pcapng'
                  copied={copiedCommand === "win"}
                  onCopy={() =>
                    handleCopy(
                      '& "C:\\Program Files\\Wireshark\\tshark.exe" -i 1 -f "udp port 500 or udp port 4500 or esp" -w ipsec_capture.pcapng',
                      "win"
                    )
                  }
                />
              </div>
            )}
          </div>

          <div className="flex items-start gap-2 px-3 py-2.5 border border-line bg-panel-2 text-xs text-ink-3">
            <Shield className="w-4 h-4 shrink-0 mt-0.5" />
            <p>
              Upload only captures you are authorized to inspect. Files are
              hashed (SHA-256) and processed locally; packet payloads are not
              sent to third parties.
            </p>
          </div>
        </div>
      )}

      {activeTab === "samples" && (
        <Card title="Sample captures" description="Verified benchmark fixtures from the TunnelTrace testbed.">
          {duplicateNotice && duplicateNotice.source === "sample" && (
            <div className="mb-4 p-3 bg-medium-bg border border-medium-border text-xs space-y-2.5">
              <div className="flex items-center gap-2 text-medium font-medium">
                <Info className="w-4 h-4 shrink-0" />
                <span>Sample already analyzed</span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() =>
                    router.push(
                      `/analyses/${duplicateNotice.existingAnalysisId}/overview`
                    )
                  }
                >
                  Open existing
                  <ArrowRight className="w-3.5 h-3.5" />
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    ingestSampleMutation.mutate({
                      sampleId: duplicateNotice.captureId,
                      forceRerun: true,
                    });
                  }}
                >
                  Force re-run
                </Button>
              </div>
            </div>
          )}

          {isSamplesLoading ? (
            <EmptyState compact title="Loading samples…" />
          ) : isSamplesError ? (
            <EmptyState
              icon={<AlertTriangle />}
              title="Sample captures could not be loaded"
              description="The local API did not return the sample register. Check that the backend is running, then try again."
              action={<Button variant="secondary" size="sm" onClick={() => refetchSamples()}>Retry</Button>}
            />
          ) : !samples || samples.length === 0 ? (
            <EmptyState
              title="No sample fixtures found"
              description="The repository has no benchmark captures available."
            />
          ) : (
            <div className="space-y-3">
              {samples.map((sample: SampleCaptureDTO) => (
                <div
                  key={sample.sample_id}
                  className="p-4 bg-panel border border-line hover:border-line-strong transition-colors space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono px-1.5 py-0.5 bg-panel-2 text-ink-3 border border-line uppercase">
                          {sample.format}
                        </span>
                        <h3 className="font-mono font-medium text-sm text-ink">
                          {sample.title}
                        </h3>
                      </div>
                      <p className="text-xs font-mono text-ink-3">
                        {sample.filename} · {sample.packet_count} packets
                      </p>
                    </div>
                    <Button
                      variant="primary"
                      size="sm"
                      disabled={ingestingSampleId === sample.sample_id}
                      onClick={() =>
                        ingestSampleMutation.mutate({
                          sampleId: sample.sample_id,
                          forceRerun: false,
                        })
                      }
                    >
                      <Play className="w-3.5 h-3.5" />
                      {ingestingSampleId === sample.sample_id
                        ? "Ingesting…"
                        : "Ingest"}
                    </Button>
                  </div>
                  <p className="text-xs text-ink-2">{sample.description}</p>
                  <div className="pt-2 border-t border-line flex flex-col sm:flex-row sm:items-center justify-between text-[11px] font-mono text-ink-3 gap-1">
                    <div className="truncate">
                      SHA-256: <span className="font-medium">{sample.sha256}</span>
                    </div>
                    <div>Provenance: {sample.provenance}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {activeTab === "live" && (
        <Card title="Live capture" description="Capture directly from a network interface.">
          <div className="space-y-4">
            <div className="p-3 bg-medium-bg border border-medium-border text-xs space-y-2 text-medium">
              <div className="flex items-center gap-2 font-medium">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Host requirements</span>
              </div>
              <p className="text-ink-2">
                Raw packet capture requires a Linux host with CAP_NET_ADMIN. On
                Windows, use a sample capture or upload a file instead.
              </p>
            </div>

            <div className="p-3 border border-line bg-panel-2 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase font-medium text-ink-3">
                  Capture agent
                </span>
                <span
                  className={`px-1.5 py-0.5 text-[11px] font-medium uppercase border ${
                    isInterfacesLoading
                      ? "bg-panel-3 text-ink-3 border-line"
                      : isInterfacesError
                      ? "bg-critical-bg text-critical border-critical-border"
                      : interfaces && interfaces.length > 0
                      ? "bg-positive-bg text-positive border-positive-border"
                      : "bg-medium-bg text-medium border-medium-border"
                  }`}
                >
                  {isInterfacesLoading
                    ? "Checking…"
                    : isInterfacesError
                    ? "Request failed"
                    : interfaces && interfaces.length > 0
                    ? "Ready"
                    : "Unavailable"}
                </span>
              </div>
              {isInterfacesLoading ? (
                <p className="text-ink-3 text-[11px]">
                  Probing capture daemon…
                </p>
              ) : isInterfacesError ? (
                <div className="space-y-2" role="alert">
                  <p className="text-critical text-[11px]">Could not reach the capture-interface service. Retry the check or use a sample or upload.</p>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="secondary" size="sm" onClick={() => refetchInterfaces()}>Retry check</Button>
                    <Button variant="primary" size="sm" onClick={() => setActiveTab("samples")}>Use a sample</Button>
                    <Button variant="secondary" size="sm" onClick={() => setActiveTab("upload")}>Upload a file</Button>
                  </div>
                </div>
              ) : interfaces && interfaces.length > 0 ? (
                <p className="text-positive text-[11px]">
                  {interfaces.length} interface(s) available.
                </p>
              ) : (
                <div className="space-y-2">
                  <p className="text-medium text-[11px]">
                    No capture daemon on this host. Use a sample or upload a
                    file.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => setActiveTab("samples")}
                    >
                      <Play className="w-3 h-3" />
                      Use a sample
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => setActiveTab("upload")}
                    >
                      Upload a file
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {interfaces && interfaces.length > 0 && (
              <div className="space-y-3 pt-1">
                <div className="space-y-1.5">
                  <label className="block text-[13px] font-medium text-ink-2">
                    Interface
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {interfaces.map((iface) => (
                      <button
                        key={iface.interface_id}
                        type="button"
                        onClick={() => setSelectedInterface(iface.interface_id)}
                        aria-pressed={selectedInterface === iface.interface_id}
                        className={`p-2.5 border text-left transition-colors ${
                          selectedInterface === iface.interface_id
                            ? "border-accent bg-accent-soft"
                            : "border-line hover:border-line-strong"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-medium text-xs text-ink">
                            {iface.display_name}
                          </span>
                          <span className="text-[11px] font-mono text-ink-3">
                            {iface.type}
                          </span>
                        </div>
                        <div className="mt-0.5 flex items-center justify-between text-[11px] text-ink-3 font-mono">
                          <span>{iface.operstate}</span>
                          <span>{iface.lab_owned ? "Lab" : "Host"}</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-[13px] font-medium text-ink-2">
                    Duration (seconds)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={300}
                    value={captureDuration}
                    onChange={(e) => setCaptureDuration(Number(e.target.value))}
                    className="w-32 h-8 px-2.5 text-[13px] bg-panel text-ink border border-line-strong font-mono focus:border-accent"
                  />
                </div>

                <div className="flex items-center gap-3">
                  {!liveSessionId ? (
                    <Button
                      variant="primary"
                      disabled={!selectedInterface}
                      onClick={handleStartLiveCapture}
                    >
                      <Play className="w-3.5 h-3.5" />
                      Start capture
                    </Button>
                  ) : (
                    <Button variant="danger" onClick={handleStopLiveCapture}>
                      <Square className="w-3.5 h-3.5" />
                      Stop & analyze
                    </Button>
                  )}
                </div>
              </div>
            )}

            {liveError && (
              <div className="p-3 bg-critical-bg border border-critical-border text-critical text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{liveError}</span>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

function CodeBlock({
  label,
  command,
  copied,
  onCopy,
}: {
  label: string;
  command: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="space-y-1 border border-line bg-panel-2 p-2.5 text-ink">
      <div className="flex items-center justify-between text-[11px] text-ink-3">
        <span>{label}</span>
        <button
          type="button"
          onClick={onCopy}
          className="flex items-center gap-1 text-xs transition-colors hover:text-ink"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-positive" />
              <span className="text-positive">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <code className="block select-all break-all font-mono text-[11px] text-ink">
        {command}
      </code>
    </div>
  );
}
