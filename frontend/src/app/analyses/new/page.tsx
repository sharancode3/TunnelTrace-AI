"use client";

import React, { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import {
  UploadCloud,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Play,
  Square,
  Shield,
  ArrowRight,
  HardDrive,
} from "lucide-react";

export default function NewAnalysisPage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Tab: "upload" vs "live"
  const [activeTab, setActiveTab] = useState<"upload" | "live">("upload");

  // Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);

  // Live Capture State
  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [captureDuration, setCaptureDuration] = useState<number>(30);
  const [liveSessionId, setLiveSessionId] = useState<string | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);

  // Fetch authorized live capture interfaces
  const { data: interfaces, isLoading: isInterfacesLoading } = useQuery({
    queryKey: ["live-interfaces"],
    queryFn: () => api.captures.listInterfaces(),
    enabled: activeTab === "live",
  });

  // Upload Mutation
  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      setUploadError(null);
      setUploadProgress(20);
      const capture = await api.captures.upload(file);
      setUploadProgress(70);
      const analysis = await api.analyses.create(capture.capture_id);
      setUploadProgress(100);
      return { capture, analysis };
    },
    onSuccess: (data) => {
      router.push(`/analyses/${data.analysis.analysis_id}/overview`);
    },
    onError: (err: any) => {
      setUploadProgress(null);
      setUploadError(err.message || "Failed to upload and initiate analysis");
    },
  });

  const handleFileSelect = (file: File) => {
    // Validate file extension
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "pcap" && ext !== "pcapng" && ext !== "cap") {
      setUploadError("Invalid file type. Supported formats: .pcap, .pcapng, .cap");
      return;
    }
    setSelectedFile(file);
    setUploadError(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleStartUpload = () => {
    if (!selectedFile) return;
    uploadMutation.mutate(selectedFile);
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

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase flex items-center space-x-2">
          <UploadCloud className="w-5 h-5 text-[#FF3D00]" />
          <span>Ingest Network Evidence & Initiate Analysis</span>
        </h1>
        <p className="text-xs text-neutral-500 mt-1">
          Upload forensic packet captures (.pcap, .pcapng) or bind to an authorized interface for live IPsec protocol ingestion.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-neutral-300 dark:border-neutral-800">
        <button
          onClick={() => setActiveTab("upload")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "upload"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          PCAP / PCAPNG Upload
        </button>
        <button
          onClick={() => setActiveTab("live")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "live"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          Authorized Live Capture
        </button>
      </div>

      {/* Tab 1: Upload */}
      {activeTab === "upload" && (
        <div className="space-y-6">
          <Card title="Forensic Evidence Ingestion">
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed p-10 text-center cursor-pointer transition-colors ${
                selectedFile
                  ? "border-[#FF3D00] bg-orange-50/20 dark:bg-orange-950/10"
                  : "border-neutral-300 dark:border-neutral-700 hover:border-neutral-400 dark:hover:border-neutral-600 bg-neutral-50/50 dark:bg-neutral-900/30"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileSelect(e.target.files[0]);
                  }
                }}
              />

              <div className="space-y-3">
                <div className="w-12 h-12 mx-auto bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 flex items-center justify-center">
                  <UploadCloud className="w-6 h-6 text-[#FF3D00]" />
                </div>

                <div className="space-y-1">
                  <p className="text-sm font-semibold text-neutral-900 dark:text-white">
                    {selectedFile
                      ? selectedFile.name
                      : "Click to select or drag & drop capture file"}
                  </p>
                  <p className="text-xs font-mono text-neutral-500">
                    Supports libpcap (.pcap), pcapng (.pcapng), and snoop/cap binary formats. Max recommended size: 250MB.
                  </p>
                </div>

                {selectedFile && (
                  <div className="inline-flex items-center space-x-2 px-3 py-1 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 text-xs font-mono">
                    <FileCode className="w-4 h-4 text-neutral-500" />
                    <span>{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</span>
                    <span className="text-emerald-600 font-bold">READY</span>
                  </div>
                )}
              </div>
            </div>

            {/* Error Message */}
            {uploadError && (
              <div className="mt-4 p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-400 dark:border-rose-800 text-rose-700 dark:text-rose-400 text-xs flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{uploadError}</span>
              </div>
            )}

            {/* Upload Progress Bar */}
            {uploadProgress !== null && (
              <div className="mt-4 space-y-1.5">
                <div className="flex justify-between text-xs font-mono text-neutral-500">
                  <span>UPLOADING & INITIALIZING ANALYSIS PIPELINE</span>
                  <span>{uploadProgress}%</span>
                </div>
                <div className="w-full bg-neutral-200 dark:bg-neutral-800 h-2">
                  <div
                    className="bg-[#FF3D00] h-2 transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="mt-6 flex justify-end">
              <button
                disabled={!selectedFile || uploadMutation.isPending}
                onClick={handleStartUpload}
                className={`flex items-center space-x-2 px-6 py-2.5 text-xs font-mono font-bold uppercase tracking-wider transition-colors ${
                  !selectedFile || uploadMutation.isPending
                    ? "bg-neutral-200 dark:bg-neutral-800 text-neutral-400 cursor-not-allowed border border-neutral-300 dark:border-neutral-700"
                    : "bg-[#FF3D00] hover:bg-[#e03600] text-white border border-[#FF3D00]"
                }`}
              >
                <span>{uploadMutation.isPending ? "PROCESSING..." : "START INGESTION"}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </Card>

          {/* Privacy & Provenance Notice */}
          <div className="p-4 border border-neutral-300 dark:border-neutral-800 bg-neutral-50/50 dark:bg-neutral-900/30 text-xs text-neutral-600 dark:text-neutral-400 space-y-2">
            <div className="flex items-center space-x-2 text-neutral-900 dark:text-white font-bold font-mono">
              <Shield className="w-4 h-4 text-[#FF3D00]" />
              <span>FORENSIC EVIDENCE INTEGRITY & PRIVACY GUARANTEE</span>
            </div>
            <p>
              Uploaded captures are hashed (SHA-256) server-side upon arrival. Raw packet payloads are never transmitted to third parties, LLM APIs, or cloud telemetry. All cryptographic evaluations and machine learning inferences execute strictly within the local container runtime.
            </p>
          </div>
        </div>
      )}

      {/* Tab 2: Live Capture */}
      {activeTab === "live" && (
        <div className="space-y-6">
          <Card title="Authorized Live Network Interface Capture">
            <div className="space-y-4">
              <p className="text-xs text-neutral-500">
                Direct live capture requires an authorized local capture agent or privileged container network namespace.
              </p>

              {isInterfacesLoading ? (
                <div className="py-6 text-center text-xs font-mono text-neutral-500 animate-pulse">
                  Querying authorized network interfaces from host...
                </div>
              ) : interfaces && interfaces.length > 0 ? (
                <div className="space-y-3">
                  <label className="block text-xs font-mono font-bold uppercase tracking-wider text-neutral-700 dark:text-neutral-300">
                    Select Capture Interface
                  </label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {interfaces.map((iface) => (
                      <div
                        key={iface.interface_id}
                        onClick={() => setSelectedInterface(iface.interface_id)}
                        className={`p-3 border cursor-pointer transition-colors ${
                          selectedInterface === iface.interface_id
                            ? "border-[#FF3D00] bg-orange-50/10 dark:bg-orange-950/20"
                            : "border-neutral-300 dark:border-neutral-800 hover:border-neutral-400"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-neutral-900 dark:text-white">
                            {iface.display_name}
                          </span>
                          <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
                            {iface.type}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center justify-between text-[11px] text-neutral-500 font-mono">
                          <span>State: {iface.operstate}</span>
                          <span>{iface.lab_owned ? "LAB TESTBED" : "HOST"}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="pt-2">
                    <label className="block text-xs font-mono font-bold uppercase tracking-wider text-neutral-700 dark:text-neutral-300 mb-1">
                      Capture Duration (Seconds)
                    </label>
                    <input
                      type="number"
                      min={5}
                      max={300}
                      value={captureDuration}
                      onChange={(e) => setCaptureDuration(Number(e.target.value))}
                      className="w-32 px-3 py-1.5 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white focus:outline-none focus:border-[#FF3D00]"
                    />
                  </div>
                </div>
              ) : (
                <div className="p-4 bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 text-xs font-mono space-y-1">
                  <div className="flex items-center space-x-2 text-amber-600 dark:text-amber-400">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="font-bold">NO CAPTURE INTERFACES ENUMERATED</span>
                  </div>
                  <p className="text-neutral-500">
                    No authorized live interfaces were detected on this runtime node. Ensure the backend capture daemon is configured or use PCAP upload.
                  </p>
                </div>
              )}

              {liveError && (
                <div className="p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-400 dark:border-rose-800 text-rose-700 dark:text-rose-400 text-xs flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{liveError}</span>
                </div>
              )}

              {/* Live Session Controls */}
              <div className="pt-4 flex items-center space-x-3">
                {!liveSessionId ? (
                  <button
                    disabled={!selectedInterface}
                    onClick={handleStartLiveCapture}
                    className={`flex items-center space-x-2 px-5 py-2 text-xs font-mono font-bold uppercase tracking-wider ${
                      !selectedInterface
                        ? "bg-neutral-200 dark:bg-neutral-800 text-neutral-400 cursor-not-allowed border border-neutral-300 dark:border-neutral-700"
                        : "bg-[#FF3D00] hover:bg-[#e03600] text-white border border-[#FF3D00]"
                    }`}
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>START LIVE CAPTURE</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStopLiveCapture}
                    className="flex items-center space-x-2 px-5 py-2 text-xs font-mono font-bold uppercase tracking-wider bg-rose-600 hover:bg-rose-700 text-white border border-rose-700 animate-pulse"
                  >
                    <Square className="w-3.5 h-3.5" />
                    <span>STOP CAPTURE & ANALYZE</span>
                  </button>
                )}
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
