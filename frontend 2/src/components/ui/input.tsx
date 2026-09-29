import React from "react";

export interface FieldProps { label: string; hint?: string; required?: boolean; error?: string; children: React.ReactNode; className?: string; }
export function Field({ label, hint, required, error, children, className = "" }: FieldProps) {
  const generatedId = React.useId();
  const child = React.isValidElement<{ id?: string }>(children) ? React.cloneElement(children, { id: children.props.id || generatedId }) : children;
  return <div className={`space-y-2 ${className}`}><div className="flex items-baseline justify-between gap-3"><label htmlFor={React.isValidElement<{ id?: string }>(child) ? child.props.id : undefined} className="text-sm font-medium">{label}{required && <span className="text-accent-ink"> *</span>}</label>{hint && <span className="text-xs text-ink-3">{hint}</span>}</div>{child}{error && <p role="alert" className="text-xs text-critical">{error}</p>}</div>;
}
type NativeInputProps = React.InputHTMLAttributes<HTMLInputElement> & { mono?: boolean };
export interface InputProps extends NativeInputProps {}
export function Input({ className = "", mono, ...props }: InputProps) { return <input className={`editorial-field h-11 w-full px-3 text-sm placeholder:text-ink-3 ${mono ? "font-mono text-xs" : ""} ${className}`} {...props} />; }
type NativeTextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean };
export interface TextareaProps extends NativeTextareaProps {}
export function Textarea({ className = "", mono, ...props }: TextareaProps) { return <textarea className={`editorial-field min-h-28 w-full resize-y px-3 py-2.5 text-sm placeholder:text-ink-3 ${mono ? "font-mono text-xs" : ""} ${className}`} {...props} />; }
export type SelectProps = React.SelectHTMLAttributes<HTMLSelectElement>;
export function Select({ className = "", ...props }: SelectProps) { return <select className={`editorial-field h-11 w-full px-3 text-sm ${className}`} {...props} />; }
