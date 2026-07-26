"use client";

import { clsx } from "clsx";
import type { ReactNode } from "react";

interface CardProps {
  title?: string;
  icon?: ReactNode;
  className?: string;
  children: ReactNode;
}

/** Glassmorphism NOC panel with an optional header. */
export function Card({ title, icon, className, children }: CardProps) {
  return (
    <section
      className={clsx(
        "glass glass-hover relative flex flex-col gap-3 rounded-2xl p-4",
        className,
      )}
    >
      {title !== undefined && (
        <header className="flex items-center gap-2 text-sm font-semibold tracking-wide text-noc-muted">
          {icon}
          <span>{title}</span>
        </header>
      )}
      {children}
    </section>
  );
}
