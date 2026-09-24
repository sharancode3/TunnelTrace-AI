import React from "react";

export type StatusType =
  | "QUEUED"
  | "RUNNING"
  | "PARTIAL"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "NO_IPSEC"
  | "UNKNOWN";

export type SeverityType =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFORMATIONAL";

export type ComplianceType =
  | "PASS"
  | "FAIL"
  | "UNKNOWN"
  | "NOT_APPLICABLE";

export type EvidenceStateType =
  | "VERIFIED"
  | "INFERRED"
  | "UNKNOWN"
  | "MISCONFIGURATION_OBSERVED";

export function StatusBadge({ status }: { status: string | null | undefined }) {
  const s = (status || "UNKNOWN").toUpperCase();

  let styles = "bg-neutral-200 text-neutral-800 border-neutral-400";
  if (s === "COMPLETED") {
    styles = "bg-emerald-100 text-emerald-900 border-emerald-500";
  } else if (s === "RUNNING") {
    styles = "bg-blue-100 text-blue-900 border-blue-500 animate-pulse";
  } else if (s === "QUEUED") {
    styles = "bg-amber-100 text-amber-900 border-amber-500";
  } else if (s === "FAILED" || s === "CANCELLED") {
    styles = "bg-rose-100 text-rose-900 border-rose-500";
  } else if (s === "PARTIAL" || s === "NO_IPSEC") {
    styles = "bg-orange-100 text-orange-900 border-orange-500";
  }

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-bold tracking-wider border ${styles}`}
    >
      {s}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const s = (severity || "INFORMATIONAL").toUpperCase();

  let styles = "bg-neutral-100 text-neutral-800 border-neutral-300";
  if (s === "CRITICAL") {
    styles = "bg-red-950 text-red-100 border-red-700";
  } else if (s === "HIGH") {
    styles = "bg-rose-100 text-rose-900 border-rose-500";
  } else if (s === "MEDIUM") {
    styles = "bg-amber-100 text-amber-900 border-amber-500";
  } else if (s === "LOW") {
    styles = "bg-blue-50 text-blue-800 border-blue-300";
  }

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-bold tracking-wider border ${styles}`}
    >
      {s}
    </span>
  );
}

export function ComplianceBadge({ state }: { state: string | null | undefined }) {
  const s = (state || "UNKNOWN").toUpperCase();

  let styles = "bg-neutral-200 text-neutral-800 border-neutral-400";
  if (s === "PASS") {
    styles = "bg-emerald-100 text-emerald-900 border-emerald-500";
  } else if (s === "FAIL") {
    styles = "bg-rose-100 text-rose-900 border-rose-500";
  } else if (s === "NOT_APPLICABLE") {
    styles = "bg-neutral-100 text-neutral-600 border-neutral-300";
  }

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-bold tracking-wider border ${styles}`}
    >
      {s}
    </span>
  );
}

export function EvidenceStateBadge({
  state,
}: {
  state: string | null | undefined;
}) {
  const s = (state || "UNKNOWN").toUpperCase();

  let styles = "bg-neutral-200 text-neutral-800 border-neutral-400";
  if (s === "VERIFIED") {
    styles = "bg-emerald-100 text-emerald-900 border-emerald-500";
  } else if (s === "INFERRED") {
    styles = "bg-sky-100 text-sky-900 border-sky-500";
  } else if (s === "MISCONFIGURATION_OBSERVED") {
    styles = "bg-amber-100 text-amber-900 border-amber-600";
  }

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium tracking-wider border ${styles}`}
    >
      {s}
    </span>
  );
}
