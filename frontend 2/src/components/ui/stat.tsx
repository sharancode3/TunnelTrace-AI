import React from "react";
export interface StatProps { label: string; value: React.ReactNode; hint?: string; tone?: "default" | "critical" | "high" | "medium" | "low" | "info" | "positive"; mono?: boolean; }
const toneClass: Record<NonNullable<StatProps["tone"]>, string> = { default: "text-ink", critical: "text-critical", high: "text-high", medium: "text-medium", low: "text-low", info: "text-ink-2", positive: "text-positive" };
export function Stat({ label, value, hint, tone = "default", mono = true }: StatProps) { return <div className="min-w-0 space-y-1 border-t border-line pt-3"><div className="micro-label text-ink-3">{label}</div><div className={`text-2xl font-medium leading-none tabular-nums tracking-tight ${toneClass[tone]} ${mono ? "font-mono" : ""}`}>{value}</div>{hint && <div className="text-xs leading-5 text-ink-3">{hint}</div>}</div>; }
export interface StatGridProps { children: React.ReactNode; className?: string; }
export function StatGrid({ children, className = "" }: StatGridProps) { return <div className={`grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3 lg:grid-cols-4 ${className}`}>{children}</div>; }
