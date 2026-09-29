import React from "react";
export type StatusType = "QUEUED" | "RUNNING" | "PARTIAL" | "COMPLETED" | "FAILED" | "CANCELLED" | "NO_IPSEC" | "UNKNOWN";
export type SeverityType = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
export type ComplianceType = "PASS" | "FAIL" | "UNKNOWN" | "NOT_APPLICABLE";
export type EvidenceStateType = "VERIFIED" | "INFERRED" | "UNKNOWN" | "MISCONFIGURATION_OBSERVED";
type Tone = "critical" | "high" | "medium" | "low" | "info" | "positive";
const tones: Record<Tone, string> = { critical: "text-critical", high: "text-high", medium: "text-medium", low: "text-low", info: "text-ink-2", positive: "text-positive" };
function Badge({ tone, children, pulse = false }: { tone: Tone; children: React.ReactNode; pulse?: boolean }) { return <span className={`inline-flex items-center gap-2 text-[.69rem] font-medium uppercase tracking-[.075em] ${tones[tone]}`}><i className={`h-1.5 w-1.5 rounded-full bg-current ${pulse ? "animate-pulse" : ""}`} aria-hidden="true" />{children}</span>; }
export function StatusBadge({ status }: { status: string | null | undefined }) { const s = (status || "UNKNOWN").toUpperCase(); const tone: Tone = s === "COMPLETED" ? "positive" : s === "RUNNING" ? "low" : s === "QUEUED" ? "medium" : s === "FAILED" || s === "CANCELLED" ? "critical" : s === "PARTIAL" || s === "NO_IPSEC" ? "high" : "info"; return <Badge tone={tone} pulse={s === "RUNNING" || s === "QUEUED"}>{s}</Badge>; }
export function SeverityBadge({ severity }: { severity: string | null | undefined }) { const s = (severity || "INFORMATIONAL").toUpperCase(); const tone: Tone = s === "CRITICAL" ? "critical" : s === "HIGH" ? "high" : s === "MEDIUM" ? "medium" : s === "LOW" ? "low" : "info"; return <Badge tone={tone}>{s}</Badge>; }
export function ComplianceBadge({ state }: { state: string | null | undefined }) { const s = (state || "UNKNOWN").toUpperCase(); return <Badge tone={s === "PASS" ? "positive" : s === "FAIL" ? "critical" : "info"}>{s.replaceAll("_", " ")}</Badge>; }
export function EvidenceStateBadge({ state }: { state: string | null | undefined }) { const s = (state || "UNKNOWN").toUpperCase(); return <Badge tone={s === "VERIFIED" ? "positive" : s === "INFERRED" ? "low" : s === "MISCONFIGURATION_OBSERVED" ? "medium" : "info"}>{s.replaceAll("_", " ")}</Badge>; }
const positiveStates = /^(VALID|VALIDATED|GOOD|MATCHED|EXACT_MATCH|CONSISTENT|ENABLED|KNOWN_ACCEPTED|NORMAL_BEHAVIOR|NOT_PRESENT_IN_THIS_SNAPSHOT|ACTIVE)$/i;
const dangerStates = /^(EXPIRED|FAILED|REVOKED|PRESENT|CONFLICT)$/i;
const warningStates = /^(DRIFT_DETECTED|DISCREPANCY_DETECTED|ANOMALOUS_BEHAVIOR|STATISTICAL_BEHAVIORAL_ANOMALY|INSUFFICIENT_EVIDENCE|NOT_YET_VALID)$/i;
export function StateText({ value, className = "" }: { value: string | null | undefined; className?: string }) { const tone = value && (positiveStates.test(value) ? "text-positive" : dangerStates.test(value) ? "text-critical" : warningStates.test(value) ? "text-high" : "text-ink-2"); return <span className={`${tone || ""} ${className}`.trim()}>{value}</span>; }
