"use client";

import { Globe } from "lucide-react";
import { ConnectionIndicator } from "@/components/ui/ConnectionIndicator";
import { useI18n } from "@/lib/i18n";

export function TopBar() {
  const { t, toggle, locale } = useI18n();
  return (
    <header className="flex flex-wrap items-center justify-between gap-3 px-1 py-4">
      <div>
        <h1 className="text-lg font-bold tracking-tight text-noc-fg">{t.title}</h1>
        <p className="text-xs text-noc-muted">{t.subtitle}</p>
      </div>
      <div className="flex items-center gap-3">
        <ConnectionIndicator />
        <button
          onClick={toggle}
          className="inline-flex items-center gap-1.5 rounded-full border border-noc-edge/60 px-3 py-1 text-xs text-noc-muted hover:border-accent-cyan/60 hover:text-noc-fg"
          aria-label="toggle language"
        >
          <Globe size={14} />
          {t.language}
          <span className="font-mono text-[10px] text-accent-cyan">{locale.toUpperCase()}</span>
        </button>
      </div>
    </header>
  );
}
