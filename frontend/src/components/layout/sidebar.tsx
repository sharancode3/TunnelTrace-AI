"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  UploadCloud,
  Network,
  GitBranch,
  Radio,
  ShieldAlert,
  FileCheck2,
  Grid,
  FileSearch,
  SlidersHorizontal,
  FileText,
  Bot,
  FlaskConical,
  Layers,
  Globe,
  ShieldCheck,
  FileKey2,
} from "lucide-react";

interface SidebarProps {
  analysisId?: string | null;
  isOpen?: boolean;
  onClose?: () => void;
}

export function Sidebar({ analysisId, isOpen = true, onClose }: SidebarProps) {
  const pathname = usePathname();
  const id = analysisId || "";

  const navigationGroups = [
    {
      title: "OPERATIONS & TELEMETRY",
      subtitle: "Live monitoring, discovery & crypto posture",
      items: [
        {
          name: "Live Monitoring",
          href: "/monitoring",
          icon: Radio,
          stageTag: "LIVE",
          disabled: false,
        },
        {
          name: "Asset Discovery",
          href: "/discovery",
          icon: Globe,
          stageTag: "STAGE 2",
          disabled: false,
        },
        {
          name: "Config & Cert Inventory",
          href: "/inventory",
          icon: FileKey2,
          stageTag: "CRYPTO",
          disabled: false,
        },
        {
          name: "Vulnerability Feed",
          href: "/vulnerabilities",
          icon: ShieldCheck,
          stageTag: "STAGE 4",
          disabled: false,
        },
      ],
    },
    {
      title: "INVESTIGATIONS",
      subtitle: "Capture ingestion & historical catalog",
      items: [
        {
          name: "New Ingest / Upload",
          href: "/analyses/new",
          icon: UploadCloud,
          disabled: false,
        },
        {
          name: "Investigation Runs",
          href: "/analyses",
          icon: Layers,
          disabled: false,
        },
      ],
    },
    {
      title: "ACTIVE RUN FORENSICS",
      subtitle: analysisId ? `Run: ${analysisId.slice(0, 8)}...` : "Select an investigation run below",
      items: [
        {
          name: "Session Overview",
          href: analysisId ? `/analyses/${id}/overview` : `/analyses`,
          icon: Activity,
          disabled: !analysisId,
        },
        {
          name: "Protocol Dissection",
          href: `/analyses/${id}/protocol`,
          icon: Network,
          disabled: !analysisId,
        },
        {
          name: "SAs & ESP Flows",
          href: `/analyses/${id}/sas`,
          icon: GitBranch,
          disabled: !analysisId,
        },
        {
          name: "Traffic & ML Intelligence",
          href: `/analyses/${id}/traffic`,
          icon: Radio,
          disabled: !analysisId,
        },
        {
          name: "Security Assessment",
          href: `/analyses/${id}/security`,
          icon: ShieldAlert,
          disabled: !analysisId,
        },
        {
          name: "Compliance Scorecard",
          href: `/analyses/${id}/compliance`,
          icon: FileCheck2,
          disabled: !analysisId,
        },
        {
          name: "Threat Matrix",
          href: `/analyses/${id}/threats`,
          icon: Grid,
          disabled: !analysisId,
        },
        {
          name: "Evidence Provenance DAG",
          href: `/analyses/${id}/evidence`,
          icon: FileSearch,
          disabled: !analysisId,
        },
      ],
    },
    {
      title: "REMEDIATION & TESTBED",
      subtitle: "Digital twin diffs & strongSwan testbed",
      items: [
        {
          name: "Configuration Security Twin",
          href: analysisId ? `/analyses/${id}/remediation` : "/lab",
          icon: SlidersHorizontal,
          stageTag: "STAGE 10",
          disabled: !analysisId,
        },
        {
          name: "Lab Testbed Orchestrator",
          href: "/lab",
          icon: FlaskConical,
          stageTag: "LAB",
          disabled: false,
        },
      ],
    },
    {
      title: "REPORTING & COPILOT",
      subtitle: "Executive export & explainable AI",
      items: [
        {
          name: "Audit & Briefing Reports",
          href: `/analyses/${id}/reports`,
          icon: FileText,
          disabled: !analysisId,
        },
        {
          name: "SOC AI Copilot",
          href: analysisId ? `/analyses/${id}/ai-analyst` : "/analyses",
          icon: Bot,
          stageTag: "STAGE 11",
          disabled: !analysisId,
        },
      ],
    },
  ];

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-40 w-64 bg-white dark:bg-[#111113] border-r border-neutral-300 dark:border-neutral-800 flex flex-col transform transition-transform duration-200 lg:static lg:translate-x-0 ${
        isOpen ? "translate-x-0" : "-translate-x-full"
      }`}
    >
      {/* Brand Header */}
      <div className="h-14 px-4 flex items-center justify-between border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-black">
        <Link href="/analyses" className="flex items-center space-x-2">
          <div className="w-5 h-5 bg-[#FF3D00] flex items-center justify-center text-white font-mono font-bold text-xs">
            T
          </div>
          <span className="font-mono font-bold text-sm tracking-widest text-neutral-900 dark:text-white uppercase">
            TunnelTrace<span className="text-[#FF3D00]">.AI</span>
          </span>
        </Link>
        <span className="text-[10px] font-mono px-1.5 py-0.5 border border-neutral-300 dark:border-neutral-700 text-neutral-500 uppercase">
          PS 160
        </span>
      </div>

      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto p-3 space-y-4">
        {navigationGroups.map((group) => (
          <div key={group.title} className="space-y-1">
            <div className="px-2 pb-0.5">
              <h4 className="text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                {group.title}
              </h4>
              {group.subtitle && (
                <p className="text-[9px] text-neutral-400 dark:text-neutral-500 leading-tight">
                  {group.subtitle}
                </p>
              )}
            </div>
            <div className="space-y-0.5 pt-0.5">
              {group.items.map((item) => {
                const isActive = (() => {
                  if (item.disabled) return false;
                  if (item.href === "/analyses") {
                    return pathname === "/analyses";
                  }
                  if (item.href === "/analyses/new") {
                    return pathname === "/analyses/new";
                  }
                  return pathname === item.href;
                })();

                const Icon = item.icon;

                if (item.disabled) {
                  return (
                    <div
                      key={item.name}
                      className="flex items-center justify-between px-2.5 py-1.5 text-xs text-neutral-400 dark:text-neutral-600 cursor-not-allowed select-none"
                      title="Select an investigation run to view this analysis"
                    >
                      <div className="flex items-center space-x-2.5">
                        <Icon className="w-3.5 h-3.5" />
                        <span className="truncate">{item.name}</span>
                      </div>
                      <span className="text-[9px] font-mono uppercase text-neutral-400 border border-neutral-200 dark:border-neutral-800 px-1 py-0.2">
                        Select Run
                      </span>
                    </div>
                  );
                }

                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={onClose}
                    className={`flex items-center justify-between px-2.5 py-1.5 text-xs transition-colors border ${
                      isActive
                        ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                        : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
                    }`}
                  >
                    <div className="flex items-center space-x-2.5">
                      <Icon className="w-3.5 h-3.5" />
                      <span className="truncate">{item.name}</span>
                    </div>
                    {item.stageTag && (
                      <span className="text-[9px] font-mono px-1 py-0.2 border border-neutral-300 dark:border-neutral-700 text-neutral-400">
                        {item.stageTag}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-neutral-300 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 text-[10px] font-mono text-neutral-500">
        <div className="flex justify-between items-center">
          <span>NTRO / SIH 2026</span>
          <span className="text-emerald-600 dark:text-emerald-400 font-bold">● ONLINE</span>
        </div>
      </div>
    </aside>
  );
}
