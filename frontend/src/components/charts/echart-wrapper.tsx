"use client";

import React, { useEffect, useRef } from "react";
import * as echarts from "echarts";

interface EChartWrapperProps {
  options: echarts.EChartsOption;
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
  theme = "light",
  accessibleSummary,
}: EChartWrapperProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const instanceRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    // Dispose old instance if theme or instance changed
    if (instanceRef.current) {
      instanceRef.current.dispose();
    }

    const chart = echarts.init(chartRef.current, theme === "dark" ? "dark" : undefined, {
      renderer: "canvas",
    });
    instanceRef.current = chart;

    chart.setOption(options);

    const resizeObserver = new ResizeObserver(() => {
      chart.resize();
    });
    resizeObserver.observe(chartRef.current);

    return () => {
      resizeObserver.disconnect();
      chart.dispose();
      instanceRef.current = null;
    };
  }, [options, theme]);

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
