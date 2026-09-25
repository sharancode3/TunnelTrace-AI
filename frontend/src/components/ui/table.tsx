"use client";

import React, { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopyableValue({
  value,
  label,
  truncate = false,
}: {
  value: string;
  label?: string;
  truncate?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const display = truncate && value.length > 16
    ? `${value.slice(0, 8)}...${value.slice(-8)}`
    : value;

  return (
    <span className="inline-flex items-center space-x-1 font-mono text-xs text-neutral-800 dark:text-neutral-200">
      <span title={value}>{display}</span>
      <button
        onClick={handleCopy}
        className="p-0.5 text-neutral-400 hover:text-neutral-900 dark:hover:text-white"
        title={label ? `Copy ${label}` : "Copy"}
        aria-label={label ? `Copy ${label}` : "Copy"}
      >
        {copied ? (
          <Check className="w-3 h-3 text-emerald-600" />
        ) : (
          <Copy className="w-3 h-3" />
        )}
      </button>
    </span>
  );
}

export function Table({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`overflow-x-auto border border-neutral-300 dark:border-neutral-800 ${className}`}>
      <table className="w-full text-left border-collapse text-xs">
        {children}
      </table>
    </div>
  );
}

export function TableHeader({ children }: { children: React.ReactNode }) {
  return (
    <thead className="bg-neutral-100 dark:bg-neutral-900/80 border-b border-neutral-300 dark:border-neutral-800 uppercase font-mono tracking-wider text-[11px] text-neutral-600 dark:text-neutral-400">
      {children}
    </thead>
  );
}

export function TableBody({ children }: { children: React.ReactNode }) {
  return (
    <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800 bg-white dark:bg-[#141416]">
      {children}
    </tbody>
  );
}

export function TableRow({
  children,
  onClick,
  isSelected = false,
  className = "",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  isSelected?: boolean;
  className?: string;
}) {
  const selectedStyle = isSelected
    ? "bg-neutral-100 dark:bg-neutral-800/80 font-medium border-l-2 border-l-[#FF3D00]"
    : "hover:bg-neutral-50 dark:hover:bg-neutral-800/40";

  return (
    <tr
      onClick={onClick}
      className={`transition-colors ${onClick ? "cursor-pointer" : ""} ${selectedStyle} ${className}`}
    >
      {children}
    </tr>
  );
}

export function TableCell({
  children,
  className = "",
  mono = false,
  colSpan,
}: {
  children: React.ReactNode;
  className?: string;
  mono?: boolean;
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={`px-3 py-2 text-neutral-800 dark:text-neutral-200 align-middle ${mono ? "font-mono" : ""} ${className}`}
    >
      {children}
    </td>
  );
}

export function TableHead({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <th className={`px-3 py-2 font-semibold ${className}`}>{children}</th>
  );
}
