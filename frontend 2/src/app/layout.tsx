import type { Metadata, Viewport } from "next";
import "./globals.css";
import { QueryProvider } from "@/lib/query-provider";
import { AnalysisProvider } from "@/lib/analysis-context";
import { AppShell } from "@/components/layout/app-shell";

export const metadata: Metadata = {
  title: "TunnelTrace.AI — From packet to proof",
  description: "Investigate IPsec captures, trace deterministic findings to packet evidence, and preserve a verifiable chain of proof.",
  manifest: "/manifest.json",
  icons: { icon: "/icon.svg", apple: "/icon.svg" },
};
export const viewport: Viewport = { themeColor: "#1f3d8f" };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body><a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:bg-ground focus:p-3">Skip to content</a><QueryProvider><AnalysisProvider><AppShell>{children}</AppShell></AnalysisProvider></QueryProvider></body></html>;
}
