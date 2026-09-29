"use client";

import { useEffect, useState } from "react";

export type ChartMode = "light" | "dark";

export function getChartMode(): ChartMode {
  if (typeof document === "undefined") return "dark";
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

export function useChartMode(): ChartMode {
  const [mode, setMode] = useState<ChartMode>(getChartMode);

  useEffect(() => {
    const root = document.documentElement;
    const sync = () =>
      setMode(root.classList.contains("dark") ? "dark" : "light");
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(root, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  return mode;
}

export interface ChartPalette {
  axis: string;
  splitLine: string;
  series: string;
}

const PALETTES: Record<ChartMode, ChartPalette> = {
  light: { axis: "#676e72", splitLine: "#c6c9ca", series: "#d9ad00" },
  dark: { axis: "#b9bec2", splitLine: "#44494c", series: "#f4c400" },
};

export function getChartPalette(mode: ChartMode): ChartPalette {
  return PALETTES[mode];
}
