"use client";
import React, { useEffect } from "react";
import { X } from "lucide-react";
export function InspectorDrawer({ isOpen, onClose, title, subtitle, badge, children, actions }: { isOpen: boolean; onClose: () => void; title: string; subtitle?: string; badge?: React.ReactNode; children: React.ReactNode; actions?: React.ReactNode }) {
  useEffect(() => { if (!isOpen) return; const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); }; window.addEventListener("keydown", onKey); return () => window.removeEventListener("keydown", onKey); }, [isOpen, onClose]);
  if (!isOpen) return null;
  return <div className="fixed inset-0 z-50 flex justify-end bg-ink/30" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><aside role="dialog" aria-modal="true" aria-label={title} className="flex h-full w-full max-w-xl flex-col overflow-hidden bg-ground shadow-2xl animate-in"><header className="flex items-start justify-between gap-4 border-b border-line px-6 py-5"><div className="space-y-2">{badge}{subtitle && <p className="font-mono text-[.69rem] text-ink-3">{subtitle}</p>}<h2 className="editorial-title text-3xl">{title}</h2></div><button type="button" onClick={onClose} className="p-2 text-ink-3 hover:text-ink" aria-label="Close inspector"><X className="h-5 w-5" /></button></header><div className="flex-1 space-y-5 overflow-y-auto px-6 py-6 text-sm">{children}</div>{actions && <footer className="flex justify-end gap-2 border-t border-line px-6 py-4">{actions}</footer>}</aside></div>;
}
