"use client";

import React, { use, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { SeverityBadge, EvidenceStateBadge } from "@/components/ui/badge";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { SecurityFindingDTO } from "@/lib/api/types";
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowRight,
  ExternalLink,
  AlertCircle,
  FileSearch,
} from "lucide-react";

export default function SecurityAssessmentPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFindingDTO | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");

  const {
    data: findings,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["findings", analysisId],
    queryFn: () => api.analyses.getFindings(analysisId),
  });

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Evaluating cryptographic policies, calculating score deductions, and compiling findings...
      </div>
    );
  }

  if (isError || !findings) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load security findings: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  const filteredFindings = findings.filter((f) => {
    const matchesSeverity =
      severityFilter === "ALL" || f.severity.toUpperCase() === severityFilter;
    const matchesSearch =
      search === "" ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      f.affected_entity.toLowerCase().includes(search.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Security Assessment & Deterministic Policy Findings
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage-8 rule evaluation, cryptographic standard violations, itemized posture score deductions, and deterministic remediation directives.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-2 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings by rule ID, title, or entity..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white placeholder-neutral-400 focus:outline-none focus:border-[#FF3D00]"
            />
          </div>
        </div>

        {/* Severity Filter Buttons */}
        <div className="flex items-center space-x-1 font-mono text-xs overflow-x-auto">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 border transition-colors ${
                severityFilter === sev
                  ? "bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 font-bold border-neutral-900 dark:border-white"
                  : "bg-white dark:bg-[#141416] text-neutral-600 dark:text-neutral-400 border-neutral-300 dark:border-neutral-800 hover:border-neutral-400"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Main Workspace (12 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Findings Table */}
        <div className={selectedFinding ? "lg:col-span-8" : "lg:col-span-12"}>
          <Card title={`Evaluated Findings (${filteredFindings.length})`}>
            {filteredFindings.length > 0 ? (
              <Table>
                <TableHeader>
                  <tr>
                    <TableHead>Severity</TableHead>
                    <TableHead>Rule ID</TableHead>
                    <TableHead>Finding Title</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Affected Entity</TableHead>
                    <TableHead>Deduction</TableHead>
                    <TableHead>Evidence</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {filteredFindings.map((finding) => (
                    <TableRow
                      key={finding.finding_id}
                      onClick={() => setSelectedFinding(finding)}
                      isSelected={selectedFinding?.finding_id === finding.finding_id}
                    >
                      <TableCell>
                        <SeverityBadge severity={finding.severity} />
                      </TableCell>
                      <TableCell mono>
                        <span className="font-semibold text-neutral-900 dark:text-white">
                          {finding.rule_id}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-bold text-neutral-900 dark:text-white">
                          {finding.title}
                        </span>
                      </TableCell>
                      <TableCell mono className="text-neutral-500 uppercase text-[11px]">
                        {finding.category}
                      </TableCell>
                      <TableCell mono className="text-neutral-600 dark:text-neutral-300 text-[11px]">
                        {finding.affected_entity}
                      </TableCell>
                      <TableCell mono>
                        <span className="font-bold text-rose-600">
                          -{finding.score_deduction}
                        </span>
                      </TableCell>
                      <TableCell>
                        <EvidenceStateBadge state={finding.evidence_state} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="py-12 text-center font-mono text-xs text-neutral-500">
                No security findings match the current filter.
              </div>
            )}
          </Card>
        </div>

        {/* Right Contextual Inspector */}
        {selectedFinding && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedFinding}
              onClose={() => setSelectedFinding(null)}
              title={selectedFinding.title}
              subtitle={`Rule: ${selectedFinding.rule_id}`}
              badge={<SeverityBadge severity={selectedFinding.severity} />}
              actions={
                <Link
                  href={`/analyses/${analysisId}/evidence?findingId=${selectedFinding.finding_id}`}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold uppercase transition-colors"
                >
                  <FileSearch className="w-3.5 h-3.5" />
                  <span>Trace Evidence DAG</span>
                </Link>
              }
            >
              <div className="space-y-4">
                {/* Score Impact */}
                <div className="p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-300 dark:border-rose-900 text-xs font-mono flex items-center justify-between">
                  <span className="text-neutral-500">Posture Score Impact:</span>
                  <span className="font-bold text-rose-600 text-sm">
                    -{selectedFinding.score_deduction} Points
                  </span>
                </div>

                {/* Technical Description */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Technical Forensics Description
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs text-neutral-700 dark:text-neutral-300 leading-relaxed font-sans">
                    {selectedFinding.technical_description}
                  </div>
                </div>

                {/* Deterministic Remediation Guidance */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Deterministic Remediation Directive
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-800 dark:text-neutral-200 leading-relaxed whitespace-pre-wrap">
                    {selectedFinding.remediation_guidance}
                  </div>
                </div>

                {/* Affected Entities & References */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                    Target Entity & Forensic Lineage
                  </span>
                  <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Affected Entity:</span>
                      <span className="font-bold">{selectedFinding.affected_entity}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Evidence State:</span>
                      <span>{selectedFinding.evidence_state}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Root Cause Key:</span>
                      <span>{selectedFinding.root_cause_key}</span>
                    </div>
                  </div>
                </div>
              </div>
            </InspectorDrawer>
          </div>
        )}
      </div>
    </div>
  );
}
