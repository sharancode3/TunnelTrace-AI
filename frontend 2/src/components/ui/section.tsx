import React from "react";

export interface SectionProps { index?: string; title: string; description?: string; actions?: React.ReactNode; children: React.ReactNode; className?: string; }
export function Section({ title, description, actions, children, className = "" }: SectionProps) {
  return <section className={`space-y-5 ${className}`}>
    <header className="flex flex-wrap items-end justify-between gap-x-8 gap-y-3 border-b border-line pb-4">
      <div className="space-y-2"><h2 className="editorial-title text-3xl sm:text-4xl">{title}</h2>{description && <p className="max-w-[68ch] text-sm leading-6 text-ink-2">{description}</p>}</div>
      {actions && <div className="shrink-0">{actions}</div>}
    </header>
    {children}
  </section>;
}
export interface SubsectionProps { title: string; children: React.ReactNode; className?: string; }
export function Subsection({ title, children, className = "" }: SubsectionProps) { return <div className={`space-y-3 ${className}`}><h3 className="font-medium tracking-tight">{title}</h3>{children}</div>; }
