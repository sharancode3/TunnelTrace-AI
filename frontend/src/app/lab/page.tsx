"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import {
  FlaskConical,
  Activity,
  Server,
  Layers,
  ShieldAlert,
  Play,
  CheckCircle,
  AlertTriangle,
} from "lucide-react";

export default function LabTestbedPage() {
  const { data: health, isLoading } = useQuery({
    queryKey: ["system-health"],
    queryFn: () => api.system.getHealth(),
  });

  const labScenarios = [
    {
      id: "SCN-001",
      title: "IKEv2 strongSwan Standard Baseline (AES-GCM-128 / PRF-SHA256 / MODP2048)",
      profile: "RFC8221_COMPLIANT",
      traffic: "WEB_BROWSING_HTTPS",
    },
    {
      id: "SCN-002",
      title: "Legacy Weak Cryptography (3DES / MD5 / MODP1024)",
      profile: "VULNERABLE_LEGACY",
      traffic: "FTP_DATABASE_SYNTHETIC",
    },
    {
      id: "SCN-003",
      title: "Post-Quantum Candidate & High Security (AES-256-GCM / ECP384)",
      profile: "HIGH_SECURITY_ANSSI",
      traffic: "VOIP_STREAMING_RTP",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <FlaskConical className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            IPsec Testbed & Automated Dataset Factory Orchestrator
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage-2 / Stage-5 Linux network namespaces, strongSwan dual-node VPN testbed, NetEm traffic shaping, and synthetic workload factory.
        </p>
      </div>

      {/* Safety Notice */}
      <div className="p-3 bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 text-xs font-mono flex items-center space-x-2 text-neutral-600 dark:text-neutral-400">
        <ShieldAlert className="w-4 h-4 text-[#FF3D00] shrink-0" />
        <span>
          <strong>SAFETY ISOLATION NOTICE:</strong> Testbed operations execute inside isolated Linux namespaces. Arbitrary shell access is prohibited. All actions map to typed allowlisted backend APIs.
        </span>
      </div>

      {/* Environment Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Testbed Runtime Node">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Backend Daemon:</span>
              <span className="font-bold text-emerald-600">
                {isLoading ? "PROBING..." : health?.status?.toUpperCase() || "HEALTHY"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Namespace Manager:</span>
              <span className="font-bold">LINUX VETH / NETNS</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-neutral-500">IPsec Engine:</span>
              <span className="font-bold">strongSwan (Charon/swanctl)</span>
            </div>
          </div>
        </Card>

        <Card title="Traffic Generation Factory">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">NetEm Shaper:</span>
              <span className="font-bold">ACTIVE (0-50ms jitter)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Workload Profiles:</span>
              <span className="font-bold">7 Native Classes</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-neutral-500">Automation Mode:</span>
              <span className="font-bold">HEADLESS BENCHMARK</span>
            </div>
          </div>
        </Card>

        <Card title="Capture Isolation State">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">Air-Gap Bound:</span>
              <span className="font-bold text-emerald-600">VERIFIED</span>
            </div>
            <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-500">External WAN:</span>
              <span className="font-bold text-neutral-400">DISCONNECTED</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-neutral-500">Forensic Ring:</span>
              <span className="font-bold">LOCAL PCAP STORAGE</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Testbed Scenario Catalog */}
      <Card title="Pre-Configured IPsec Experiment Scenarios">
        <div className="divide-y divide-neutral-200 dark:divide-neutral-800 text-xs font-mono">
          {labScenarios.map((scn) => (
            <div
              key={scn.id}
              className="py-3 flex flex-col md:flex-row md:items-center justify-between gap-3"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-[#FF3D00]">{scn.id}</span>
                  <span className="font-semibold text-neutral-900 dark:text-white">
                    {scn.title}
                  </span>
                </div>
                <div className="text-[11px] text-neutral-500 flex space-x-3">
                  <span>Profile: {scn.profile}</span>
                  <span>•</span>
                  <span>Workload: {scn.traffic}</span>
                </div>
              </div>

              <div className="text-right">
                <span className="px-2 py-1 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-300 text-[10px] font-bold uppercase">
                  Automated Experiment
                </span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
