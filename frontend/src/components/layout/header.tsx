"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { Menu, Plus, Radio, Sun, Moon, ChevronRight } from "lucide-react";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge } from "../ui/badge";

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export function Header({ onToggleSidebar }: HeaderProps) {
  const { activeAnalysisId, analysis, overview, wsConnected } = useAnalysis();
  const [theme, setTheme] = useState<"light" | "dark">("light");

  useEffect(() => {
    // Check initial system or stored theme
    if (
      localStorage.theme === "dark" ||
      (!("theme" in localStorage) &&
        window.matchMedia("(prefers-color-scheme: dark)").matches)
    ) {
      document.documentElement.classList.add("dark");
      setTheme("dark");
    } else {
      document.documentElement.classList.remove("dark");
      setTheme("light");
    }
  }, []);

  const toggleTheme = () => {
    if (theme === "light") {
      document.documentElement.classList.add("dark");
      localStorage.theme = "dark";
      setTheme("dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.theme = "light";
      setTheme("light");
    }
  };

  return (
    <header className="h-14 bg-white dark:bg-[#111113] border-b border-neutral-300 dark:border-neutral-800 px-4 flex items-center justify-between">
      {/* Left: Mobile Toggle & Active Context */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-1.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-300"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Active Analysis Context Display */}
        {activeAnalysisId ? (
          <div className="flex items-center space-x-2 text-xs">
            <span className="font-mono text-neutral-400 uppercase">RUN:</span>
            <span className="font-mono font-bold text-neutral-900 dark:text-white">
              {activeAnalysisId.slice(0, 8)}...
            </span>
            {overview?.capture?.filename && (
              <>
                <ChevronRight className="w-3.5 h-3.5 text-neutral-400" />
                <span className="font-mono text-neutral-600 dark:text-neutral-400 truncate max-w-[200px]">
                  {overview.capture.filename}
                </span>
              </>
            )}
            {analysis?.status && (
              <StatusBadge status={analysis.status} />
            )}
          </div>
        ) : (
          <div className="text-xs font-mono text-neutral-500 uppercase">
            No Active Analysis Run Selected
          </div>
        )}
      </div>

      {/* Right: Status Indicators & Actions */}
      <div className="flex items-center space-x-4">
        {/* Realtime WebSocket indicator */}
        <div className="flex items-center space-x-1.5 text-[11px] font-mono">
          <Radio
            className={`w-3.5 h-3.5 ${
              wsConnected ? "text-emerald-500 animate-pulse" : "text-neutral-400"
            }`}
          />
          <span className="hidden sm:inline text-neutral-500">
            {wsConnected ? "STREAM ACTIVE" : "DISCONNECTED"}
          </span>
        </div>

        {/* New Ingest CTA */}
        <Link
          href="/analyses/new"
          className="flex items-center space-x-1 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-3 py-1.5 border border-[#FF3D00] transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span className="hidden md:inline uppercase">New Ingest</span>
        </Link>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-1.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
          title={`Switch to ${theme === "light" ? "Dark" : "Light"} theme`}
          aria-label={`Switch to ${theme === "light" ? "Dark" : "Light"} theme`}
        >
          {theme === "light" ? (
            <Moon className="w-4 h-4" />
          ) : (
            <Sun className="w-4 h-4" />
          )}
        </button>
      </div>
    </header>
  );
}
