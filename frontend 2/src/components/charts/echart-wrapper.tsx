"use client";

import React, { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, TreeChart } from "echarts/charts";
import { 
  TitleComponent, 
  TooltipComponent, 
  GridComponent, 
  LegendComponent, 
  DataZoomComponent,
  DatasetComponent
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { useChartMode } from "./chart-theme";

echarts.use([
  BarChart, TreeChart,
  TitleComponent, TooltipComponent, GridComponent, LegendComponent, DataZoomComponent, DatasetComponent,
  CanvasRenderer
]);

interface EChartWrapperProps {
  options: echarts.EChartsCoreOption;
  height?: string | number;
  width?: string | number;
  className?: string;
  theme?: "light" | "dark";
  accessibleSummary?: string;
}

export function EChartWrapper({
  options,
  height = "300px",
  width = "100%",
  className = "",
  theme,
  accessibleSummary,
}: EChartWrapperProps) {
  const mode = useChartMode();
  const resolvedTheme = theme ?? mode;
  const chartRef = useRef<HTMLDivElement>(null);
  const instanceRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    // Dispose old instance if theme changed
    if (instanceRef.current) {
      instanceRef.current.dispose();
    }

    const chart = echarts.init(chartRef.current, resolvedTheme === "dark" ? "dark" : undefined, {
      renderer: "canvas",
    });
    instanceRef.current = chart;

    const reducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Initial option set
    if (options) {
      chart.setOption({
        animation: !reducedMotion,
        animationDuration: 600,
        animationDurationUpdate: 450,
        animationEasing: "exponentialOut",
        animationEasingUpdate: "exponentialOut",
        animationDelay: (index: number) => Math.min(index, 10) * 35,
        ...options,
      });
    }

    let resizeAnimationFrame: number;
    const resizeObserver = new ResizeObserver(() => {
      if (resizeAnimationFrame) cancelAnimationFrame(resizeAnimationFrame);
      resizeAnimationFrame = requestAnimationFrame(() => {
        chart.resize();
      });
    });
    resizeObserver.observe(chartRef.current);

    return () => {
      resizeObserver.disconnect();
      if (resizeAnimationFrame) cancelAnimationFrame(resizeAnimationFrame);
      chart.dispose();
      instanceRef.current = null;
    };
  }, [resolvedTheme]); // only re-init if theme changes

  // Update options without destroying the chart
  useEffect(() => {
    if (instanceRef.current && options) {
      instanceRef.current.setOption(options, { notMerge: false });
    }
  }, [options]);

  return (
    <div className={`relative ${className}`}>
      {accessibleSummary && (
        <span className="sr-only">{accessibleSummary}</span>
      )}
      <div
        ref={chartRef}
        style={{ height, width }}
        aria-hidden="true"
      />
    </div>
  );
}
