import React from "react";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "active" | "subtle" | "danger";
  title?: string;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
}

export function Card({
  children,
  className = "",
  variant = "default",
  title,
  badge,
  actions,
  ...props
}: CardProps) {
  let borderStyle = "border-neutral-300 dark:border-neutral-800";
  if (variant === "active") {
    borderStyle = "border-[#FF3D00]";
  } else if (variant === "danger") {
    borderStyle = "border-rose-600";
  }

  return (
    <div
      className={`bg-white dark:bg-[#141416] border ${borderStyle} ${className}`}
      {...props}
    >
      {(title || badge || actions) && (
        <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 px-4 py-2.5 bg-neutral-50/50 dark:bg-neutral-900/50">
          <div className="flex items-center space-x-2">
            {title && (
              <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-800 dark:text-neutral-200">
                {title}
              </h3>
            )}
            {badge}
          </div>
          {actions && <div className="flex items-center space-x-2">{actions}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
