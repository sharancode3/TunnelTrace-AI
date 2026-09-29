"use client";
import React, { useEffect, useRef, useState } from "react";
export function Reveal({ children, className = "", delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) {
  const ref = useRef<HTMLDivElement>(null); const [visible, setVisible] = useState(false);
  useEffect(() => { document.documentElement.classList.add("motion-ready"); if (!ref.current || window.matchMedia("(prefers-reduced-motion: reduce)").matches) { setVisible(true); return; } const observer = new IntersectionObserver(([entry]) => { if (entry.isIntersecting) { setVisible(true); observer.disconnect(); } }, { threshold: .08, rootMargin: "0px 0px -5% 0px" }); observer.observe(ref.current); return () => observer.disconnect(); }, []);
  return <div ref={ref} className={`reveal ${visible ? "is-visible" : ""} ${className}`} style={{ transitionDelay: `${delay}ms` }}>{children}</div>;
}
