"use client";

import React, { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Section } from "@/components/ui/section";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Stat, StatGrid } from "@/components/ui/stat";
import { ComplianceBadge, SeverityBadge } from "@/components/ui/badge";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { CopyableValue } from "@/components/ui/table";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ComplianceEvaluationDTO } from "@/lib/api/types";
import {
  Search,
  CheckCircle,
  XCircle,
  HelpCircle,
  MinusCircle,
  AlertTriangle,
} from "lucide-react";

const RESULT_FILTERS = ["ALL", "PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"];

export default function ComplianceScorecardPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [selectedRule, setSelectedRule] = useState<ComplianceEvaluationDTO | null>(null);
  const [resultFilter, setResultFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");

  const {
    data: compliance,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["compliance", analysisId],
    queryFn: () => api.analyses.getCompliance(analysisId),
  });

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <EmptyState
          compact
          title="Evaluating compliance rules…"
          description="Running the policy bundle across standards profiles for this capture."
        />
      </div>
    );
  }

  if (isError || !compliance) {
    return (
      <div role="alert">
        <EmptyState
          icon={<AlertTriangle />}
          title="Failed to load compliance scorecard"
          description={(error as any)?.message || "Unknown error"}
          action={
            <Button variant="secondary" size="sm" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  const filteredEvaluations = (compliance.evaluations || []).filter((ev) => {
    const matchesResult =
      resultFilter === "ALL" || ev.compliance_state.toUpperCase() === resultFilter;
    const matchesSearch =
      search === "" ||
      ev.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      (ev.rule_title || "").toLowerCase().includes(search.toLowerCase()) ||
      (ev.category || "").toLowerCase().includes(search.toLowerCase()) ||
      (ev.standard || "").toLowerCase().includes(search.toLowerCase());
    return matchesResult && matchesSearch;
  });

  const filterActive =
    "bg-accent-press text-on-accent border-accent font-semibold";
  const filterIdle =
    "bg-panel text-ink-2 border-line hover:border-line-strong hover:text-ink";

  return (
    <div className="space-y-5 max-w-6xl mx-auto">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold text-ink tracking-tight">
          Compliance Scorecard
        </h1>
        <p className="text-[13px] text-ink-2">
          Automated pass/fail/unknown checks against NIST SP 800-77 Rev 1 and RFC
          8221. Rules without captured packet evidence are truthfully labelled
          UNKNOWN — never coerced to FAIL.
        </p>
      </header>

      <Section
        index="§1"
        title="Scorecard"
        description="Evaluated profile, rule outcomes, and the epistemic integrity rules behind the scoring."
      >
        <div className="border border-line bg-panel">
          <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-line">
            <div className="space-y-1">
              <div className="text-[13px] font-semibold text-ink font-mono">
                {compliance.profile_name}
              </div>
              <div className="text-[11px] font-mono text-ink-3 flex flex-wrap items-center gap-x-3 gap-y-1">
                <span>Profile: {compliance.profile_id}</span>
                <span className="flex items-center gap-1.5">
                  Bundle hash:{" "}
                  {compliance.policy_bundle_hash ? (
                    <CopyableValue
                      value={compliance.policy_bundle_hash}
                      truncate
                      label="Policy bundle hash"
                    />
                  ) : (
                    <span>N/A</span>
                  )}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <span className="text-[11px] uppercase tracking-wide text-ink-3">
                Total rule evaluations
              </span>
              <span className="font-mono text-2xl font-bold text-ink leading-none">
                {compliance.total_evaluations}
              </span>
            </div>
          </div>

          <div className="p-4">
            <StatGrid>
              <Stat
                label="Pass"
                value={
                  <span className="flex items-center gap-1.5">
                    <CheckCircle className="w-4 h-4" />
                    {compliance.pass_count}
                  </span>
                }
                hint="checks met on observed evidence"
              />
              <Stat
                label="Fail"
                value={
                  <span className="flex items-center gap-1.5">
                    <XCircle className="w-4 h-4" />
                    {compliance.fail_count}
                  </span>
                }
                tone={compliance.fail_count > 0 ? "critical" : "default"}
                hint="requirement not satisfied"
              />
              <Stat
                label="Unknown"
                value={
                  <span className="flex items-center gap-1.5">
                    <HelpCircle className="w-4 h-4" />
                    {compliance.unknown_count}
                  </span>
                }
                tone="info"
                hint="not assessable from capture"
              />
              <Stat
                label="Not Applicable"
                value={
                  <span className="flex items-center gap-1.5">
                    <MinusCircle className="w-4 h-4" />
                    {compliance.not_applicable_count}
                  </span>
                }
                tone="info"
                hint="out of scope for this profile"
              />
            </StatGrid>
          </div>

          <div className="px-4 py-3 border-t border-line bg-panel-2 text-[11px] font-mono text-ink-3 space-y-1">
            <span className="font-semibold text-ink-2">
              Epistemic integrity notice:
            </span>
            <span className="block">
              • UNKNOWN is never coerced to FAIL. • NOT_APPLICABLE is never
              counted as PASS.
            </span>
          </div>
        </div>
      </Section>

      <Section
        index="§2"
        title="Rule Evaluations"
        description="Every deterministic rule assertion for this run. Select a row for observed value, expected requirement, and rationale."
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative w-full sm:max-w-sm">
            <Search className="w-4 h-4 text-ink-3 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <Input
              type="text"
              mono
              placeholder="Search rules by ID, standard, or title…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search compliance rules"
              className="pl-8"
            />
          </div>

          <div
            role="group"
            aria-label="Filter rules by compliance state"
            className="flex items-center gap-1 overflow-x-auto"
          >
            {RESULT_FILTERS.map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setResultFilter(st)}
                aria-pressed={resultFilter === st}
                className={`px-2.5 py-1.5 border font-mono text-xs ${
                  resultFilter === st ? filterActive : filterIdle
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          <div className={selectedRule ? "lg:col-span-8" : "lg:col-span-12"}>
            {filteredEvaluations.length > 0 ? (
              <div className="border border-line bg-panel p-4">
                <div className="flex items-baseline justify-between gap-3 pb-3">
                  <span className="text-[13px] font-semibold text-ink">
                    Evaluated compliance rules ({filteredEvaluations.length})
                  </span>
                  <span className="text-[11px] font-mono text-ink-3">
                    of {compliance.total_evaluations} total
                  </span>
                </div>

                <Table>
                  <TableHeader>
                    <tr>
                      <TableHead>Result</TableHead>
                      <TableHead>Rule ID</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Standard</TableHead>
                      <TableHead>Severity</TableHead>
                    </tr>
                  </TableHeader>
                  <TableBody>
                    {filteredEvaluations.map((ev) => (
                      <TableRow
                        key={ev.rule_id}
                        onClick={() => setSelectedRule(ev)}
                        isSelected={selectedRule?.rule_id === ev.rule_id}
                      >
                        <TableCell>
                          <ComplianceBadge state={ev.compliance_state} />
                        </TableCell>
                        <TableCell mono>
                          <span className="font-semibold text-ink">{ev.rule_id}</span>
                        </TableCell>
                        <TableCell>
                          <span className="font-semibold text-ink">{ev.rule_title}</span>
                        </TableCell>
                        <TableCell mono className="text-ink-3 uppercase text-[11px]">
                          {ev.category}
                        </TableCell>
                        <TableCell mono className="text-ink-2 text-[11px]">
                          {ev.standard}
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={ev.severity} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="border border-line bg-panel">
                <EmptyState
                  icon={<Search />}
                  title="No compliance rules match the active filter"
                  description="Adjust the search text or choose a different result state to see evaluations."
                  action={
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setSearch("");
                        setResultFilter("ALL");
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              </div>
            )}
          </div>

          {/* Right Contextual Inspector */}
          {selectedRule && (
            <div className="lg:col-span-4">
              <InspectorDrawer
                isOpen={!!selectedRule}
                onClose={() => setSelectedRule(null)}
                title={selectedRule.rule_title}
                subtitle={`Standard: ${selectedRule.standard}`}
                badge={<ComplianceBadge state={selectedRule.compliance_state} />}
              >
                <div className="space-y-4">
                  {/* Rule identity */}
                  <div className="p-2.5 bg-panel-2 border border-line text-xs font-mono space-y-1">
                    <div className="flex justify-between gap-3">
                      <span className="text-ink-3">Rule ID:</span>
                      <span className="font-semibold text-ink">{selectedRule.rule_id}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span className="text-ink-3">Category:</span>
                      <span className="text-ink">{selectedRule.category}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span className="text-ink-3">Evidence State:</span>
                      <span className="text-ink">{selectedRule.evidence_state}</span>
                    </div>
                  </div>

                  {/* Values comparison */}
                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                      Observed vs. Expected
                    </span>
                    <div className="space-y-2 font-mono text-xs">
                      <div className="p-2.5 bg-panel-2 border border-line space-y-0.5">
                        <span className="text-[11px] text-ink-3 uppercase">
                          Observed Value
                        </span>
                        <pre className="text-ink font-semibold whitespace-pre-wrap break-all">
                          {JSON.stringify(selectedRule.observed_value, null, 2) || "None"}
                        </pre>
                      </div>

                      <div className="p-2.5 bg-panel-2 border border-line space-y-0.5">
                        <span className="text-[11px] text-ink-3 uppercase">
                          Expected Requirement
                        </span>
                        <pre className="text-ink font-semibold whitespace-pre-wrap break-all">
                          {JSON.stringify(selectedRule.expected_value, null, 2) || "None"}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Evaluation rationale */}
                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 font-semibold block mb-1">
                      Evaluation Rationale
                    </span>
                    <div className="p-3 bg-panel-2 border border-line text-[13px] text-ink-2 leading-relaxed">
                      {selectedRule.rationale}
                    </div>
                  </div>
                </div>
              </InspectorDrawer>
            </div>
          )}
        </div>
      </Section>
    </div>
  );
}
