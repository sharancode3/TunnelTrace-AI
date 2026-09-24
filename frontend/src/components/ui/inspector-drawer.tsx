"use client";

import React from "react";
import { X } from "lucide-react";

interface InspectorDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  badge?: React.ReactNode;
  children: React.ReactNode;
  actions?: React.ReactNode;
}

export function InspectorDrawer({
  isOpen,
  onClose,
  title,
  subtitle,
  badge,
  children,
  actions,
}: InspectorDrawerProps) {
  if (!isOpen) return null;

  return (
    <div className="flex flex-col h-full bg-white dark:bg-[#141416] border-l border-neutral-300 dark:border-neutral-800 shadow-none">
      {/* Header */}
      <div className="flex items-start justify-between p-4 border-b border-neutral-200 dark:border-neutral-800 bg-neutral-50/50 dark:bg-neutral-900/50">
        <div className="space-y-1 pr-2">
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-neutral-500">
              Contextual Inspector
            </span>
            {badge}
          </div>
          <h2 className="text-sm font-bold text-neutral-900 dark:text-white leading-snug">
            {title}
          </h2>
          {subtitle && (
            <p className="text-xs font-mono text-neutral-500 dark:text-neutral-400">
              {subtitle}
            </p>
          )}
        </div>
        <button
          onClick={onClose}
          className="p-1 text-neutral-400 hover:text-neutral-900 dark:hover:text-white transition-colors"
          aria-label="Close inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs text-neutral-800 dark:text-neutral-200">
        {children}
      </div>

      {/* Footer / Actions */}
      {actions && (
        <div className="p-3 border-t border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 flex items-center justify-end space-x-2">
          {actions}
        </div>
      )}
    </div>
  );
}
