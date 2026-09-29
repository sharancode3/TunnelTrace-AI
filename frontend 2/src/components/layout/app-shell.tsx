"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight, ChevronDown, Menu, X } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { useAnalysis } from "@/lib/analysis-context";

const secondaryRoutes = [
  ["Asset discovery", "/discovery"],
  ["Lab & testbed", "/lab"],
  ["How it works", "/how-it-works"],
] as const;

const primaryRoutes = [
  ["Investigations", "/analyses"],
  ["Monitoring", "/monitoring"],
  ["Assets", "/inventory"],
  ["Vulnerabilities", "/vulnerabilities"],
] as const;

function SiteLink({ href, children, current }: { href: string; children: React.ReactNode; current: boolean }) {
  return <Link href={href} aria-current={current ? "page" : undefined} className="site-nav-link">{children}</Link>;
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() || "/";
  const { activeAnalysisId } = useAnalysis();
  const [moreOpen, setMoreOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const { data: readiness, isError, isLoading } = useQuery({ queryKey: ["system-readiness"], queryFn: () => api.system.getReadiness(), refetchInterval: 30000 });
  const apiStatus = isError ? "API offline" : readiness?.status === "READY" ? "API ready" : readiness?.status ? `API · ${readiness.status.replaceAll("_", " ").toLowerCase()}` : isLoading ? "Checking API" : "API status unavailable";
  const evidenceHref = activeAnalysisId ? `/analyses/${activeAnalysisId}/evidence` : "/analyses?action=select_run";
  const evidenceCurrent = pathname.includes("/evidence");

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  useEffect(() => { setMoreOpen(false); setMobileOpen(false); }, [pathname]);
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setMoreOpen(false); setMobileOpen(false); }
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, []);

  return <div className="site-shell">
    <header className="site-header border-b border-line" data-scrolled={scrolled}>
      <div className="header-inner flex min-h-[4.6rem] items-center justify-between gap-4">
        <Link href="/" aria-label="TunnelTrace.AI home" className="site-wordmark flex shrink-0 items-center gap-2"><svg viewBox="0 0 34 24" aria-hidden="true" className="h-6 w-9"><path d="M2 12h11m8 0h11" stroke="#f4c400" strokeWidth="4"/><circle cx="17" cy="12" r="6.5" fill="white" stroke="#101113" strokeWidth="2"/></svg><span>TunnelTrace<span className="align-top font-sans text-[.58rem] font-semibold tracking-normal">.AI</span></span></Link>

        <nav aria-label="Primary navigation" className="hidden items-center gap-1 xl:flex">
          {primaryRoutes.map(([label, href]) => <SiteLink key={href} href={href} current={href === "/analyses" ? pathname.startsWith("/analyses") : pathname.startsWith(href)}>{label}</SiteLink>)}
          <SiteLink href={evidenceHref} current={evidenceCurrent}>Evidence</SiteLink>
          <div className="relative">
            <button type="button" className="site-nav-link inline-flex items-center gap-1" aria-haspopup="true" aria-expanded={moreOpen} aria-controls="more-navigation" onClick={() => setMoreOpen((open) => !open)}>More<ChevronDown className={`h-3.5 w-3.5 transition-transform ${moreOpen ? "rotate-180" : ""}`} /></button>
            <div id="more-navigation" className="nav-expand" data-open={moreOpen} aria-hidden={!moreOpen} inert={!moreOpen}>
              <div><div role="menu" aria-label="More tools">{secondaryRoutes.map(([label, href]) => <Link key={href} href={href} role="menuitem" className="text-sm font-semibold transition-colors"><span>{label}</span><ArrowUpRight className="h-4 w-4 shrink-0" /></Link>)}</div></div>
            </div>
          </div>
        </nav>

        <div className="flex shrink-0 items-center gap-2 sm:gap-3">
          <div className="flex items-center gap-2 text-[.63rem] uppercase tracking-[.08em] text-white/80" title={apiStatus} aria-live="polite"><span className={`h-1.5 w-1.5 rounded-full ${isError || readiness?.status === "FAILED" ? "bg-critical" : readiness?.status === "READY" ? "bg-accent" : "bg-white/60"}`} /><span className="hidden sm:inline">{apiStatus}</span><span className="sr-only sm:hidden">{apiStatus}</span></div>
          <Link href="/analyses/new" className="editorial-btn editorial-btn-primary inline-flex min-h-10 items-center gap-2 px-3 text-xs font-medium sm:px-4 sm:text-sm">New analysis<ArrowUpRight className="h-4 w-4" /></Link>
          <button type="button" onClick={() => setMobileOpen((open) => !open)} aria-label={mobileOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileOpen} aria-controls="mobile-navigation" className="grid h-10 w-10 place-items-center border border-white/50 text-white xl:hidden">{mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}</button>
        </div>
      </div>

      <div id="mobile-navigation" className="nav-expand border-t border-line bg-ground xl:hidden" data-open={mobileOpen} aria-hidden={!mobileOpen} inert={!mobileOpen}>
        <div><nav aria-label="Mobile navigation" className="header-inner grid py-3">
          {primaryRoutes.map(([label, href]) => <Link key={href} href={href} aria-current={href === "/analyses" ? pathname.startsWith("/analyses") ? "page" : undefined : pathname.startsWith(href) ? "page" : undefined} className="border-b border-line py-3 text-[15px]">{label}<ArrowUpRight className="ml-1 inline h-4 w-4" /></Link>)}
          <Link href={evidenceHref} aria-current={evidenceCurrent ? "page" : undefined} className="border-b border-line py-3 text-[15px]">Evidence<ArrowUpRight className="ml-1 inline h-4 w-4" /></Link>
          {secondaryRoutes.map(([label, href]) => <Link key={href} href={href} className="border-b border-line py-3 text-[15px]">{label}<ArrowUpRight className="ml-1 inline h-4 w-4" /></Link>)}
        </nav></div>
      </div>
    </header>
    <main id="main-content" className="min-h-[calc(100svh-6rem)]"><div key={pathname} className="route-content animate-in">{children}</div></main>
    <footer className="border-t border-line"><div className="page-wrap flex flex-wrap items-center justify-between gap-3 py-6 text-[.68rem] text-ink-3"><span>Deterministic IPsec investigation · processed locally</span><span className="font-mono">TUNNELTRACE.AI</span></div></footer>
  </div>;
}
