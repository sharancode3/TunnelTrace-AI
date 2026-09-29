import React from "react";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> { title?: string; description?: string; actions?: React.ReactNode; children: React.ReactNode; padded?: boolean; }
export function Card({ title, description, actions, children, padded = true, className = "", ...props }: CardProps) {
  return <section className={`min-w-0 border-y border-line ${className}`} {...props}>
    {(title || description || actions) && <header className="flex items-end justify-between gap-4 border-b border-line py-4">
      <div>{title && <h3 className="editorial-title text-2xl">{title}</h3>}{description && <p className="mt-1 max-w-[65ch] text-sm text-ink-2">{description}</p>}</div>{actions}
    </header>}
    <div className={padded ? "py-5 sm:py-7" : ""}>{children}</div>
  </section>;
}
