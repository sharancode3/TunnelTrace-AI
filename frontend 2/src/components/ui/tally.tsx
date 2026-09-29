"use client";
import React from "react";
import { useCountUp } from "@/lib/motion";
export interface TallyProps { value: number | null | undefined; decimals?: number; prefix?: string; suffix?: string; duration?: number; delay?: number; className?: string; }
export function Tally({ value, decimals = 0, prefix = "", suffix = "", duration = 800, delay = 0, className = "" }: TallyProps) { const shown = useCountUp(value, { duration, delay, decimals }); const valid = value != null && Number.isFinite(Number(value)); return <span className={className}>{valid ? `${prefix}${shown}${suffix}` : "N/A"}</span>; }
