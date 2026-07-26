"use client";

import { useState, useEffect, useCallback } from "react";
import { clsx } from "clsx";
import { Wand2, ShieldCheck, RefreshCw, Plus, Clock } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8080";

interface DraftEntry {
  name: string;
  platform: string;
  uri: string;
  icon: string;
  priority: number;
  status: string;
  sourceCheckedAt: string;
  note?: string;
}

export function ClientDraft() {
  const [docsUrl, setDocsUrl] = useState("");
  const [drafts, setDrafts] = useState<DraftEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [flash, setFlash] = useState("");

  const refresh = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/admin/clients/drafts`);
      if (!res.ok) return;
      const data = (await res.json()) as { drafts: DraftEntry[] };
      setDrafts(data.drafts ?? []);
    } catch {
      /* offline */
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const draft = useCallback(async () => {
    if (!docsUrl.trim()) return;
    setBusy(true); setError(""); setFlash("");
    try {
      const res = await fetch(`${API_BASE}/v1/admin/clients/draft`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ docs_url: docsUrl.trim() }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.error ?? `draft failed: ${res.status}`);
      }
      const data = (await res.json()) as { draft: DraftEntry };
      setFlash(`AI drafted "${data.draft.name}" — pending human review`);
      setDocsUrl("");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "draft failed");
    } finally { setBusy(false); }
  }, [docsUrl, refresh]);

  const confirm = useCallback(async (name: string) => {
    setBusy(true); setError("");
    try {
      const res = await fetch(`${API_BASE}/v1/admin/clients/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      if (!res.ok) throw new Error(`confirm failed: ${res.status}`);
      setFlash(`"${name}" confirmed — now served to subscribers`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "confirm failed");
    } finally { setBusy(false); }
  }, [refresh]);

  return (
    <div className="min-h-screen bg-noc-bg p-4 md:p-8" dir="rtl">
      <style>{`
        @keyframes rgb-flow { 0%,100%{background-position:0% 50%} 50%{background-position:100% 50%} }
        .rgb-border{background:linear-gradient(135deg,rgb(0 240 255/.55),rgb(139 92 246/.55),rgb(236 72 153/.55),rgb(0 240 255/.55));background-size:300% 300%;animation:rgb-flow 6s ease infinite;box-shadow:0 0 18px rgb(139 92 246/.35)}
      `}</style>

      <div className="mx-auto max-w-2xl space-y-4">
        {/* Header */}
        <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
          <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
            <h1 className="bg-gradient-to-r from-cyan-400 via-fuchsia-400 to-cyan-400 bg-clip-text text-2xl font-bold text-transparent">
              Client Registry · AI Draft
            </h1>
            <p className="mt-1 text-sm text-noc-muted">
              لینک مستندات کلاینت جدید را بچسبانید — هوش مصنوعی پیش‌نویس می‌سازد، شما تأیید می‌کنید. کلاینت تأییدنشده هرگز به مشترک نمایش داده نمی‌شود.
            </p>
          </div>
        </div>

        {/* Draft form */}
        <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
          <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md space-y-3">
            <label className="block">
              <span className="mb-1 flex items-center gap-1 text-xs text-noc-muted"><Plus size={14} /> لینک مستندات / GitHub / App Store</span>
              <input
                data-testid="docs-url-input" dir="ltr" value={docsUrl}
                onChange={(e) => setDocsUrl(e.target.value)}
                placeholder="https://github.com/acme/NovaVPN"
                className="w-full rounded-md border border-noc-edge/60 bg-noc-bg/50 px-3 py-2 text-sm text-noc-fg outline-none focus:border-accent-cyan/70"
              />
            </label>
            <button data-testid="draft-btn" onClick={draft} disabled={busy || !docsUrl.trim()}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500/25 via-fuchsia-500/25 to-cyan-500/25 px-4 py-2.5 text-sm font-bold text-cyan-200 transition-all hover:from-cyan-500/40 hover:to-fuchsia-500/40 disabled:opacity-50">
              <Wand2 size={16} /> {busy ? "…" : "پیش‌نویس با هوش مصنوعی — Draft"}
            </button>
            <div className="flex items-center justify-between">
              <button data-testid="refresh-btn" onClick={refresh} className="flex items-center gap-1 text-xs text-noc-muted hover:text-noc-fg"><RefreshCw size={12} />refresh</button>
              {error && <span data-testid="draft-error" className="text-xs text-red-400">{error}</span>}
              {flash && <span data-testid="draft-flash" className="text-xs text-emerald-300">{flash}</span>}
            </div>
          </div>
        </div>

        {/* Drafts list */}
        <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
          <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
            <div className="mb-3 flex items-center gap-2 text-sm text-noc-muted">
              <Clock size={14} /> پیش‌نویس‌ها — Drafts ({drafts.length})
            </div>
            <div data-testid="drafts-list" className="space-y-2">
              {drafts.length === 0 ? (
                <p data-testid="empty-drafts" className="text-xs text-noc-muted">هنوز پیش‌نویسی وجود ندارد — لینک را بچسبانید.</p>
              ) : (
                drafts.map((d) => (
                  <div key={d.name} data-testid={`draft-row-${d.name}`} className="flex items-center justify-between rounded-lg border border-noc-edge/40 bg-noc-bg/40 px-3 py-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm text-noc-fg">{d.name} <span className="text-xs text-noc-muted">· {d.platform}</span></p>
                      {d.note && <p className="truncate text-[11px] text-noc-muted" dir="rtl">{d.note}</p>}
                    </div>
                    <span className={clsx("ml-2 shrink-0 rounded-full border px-2 py-0.5 text-[11px]",
                      d.status === "confirmed" ? "border-emerald-400/50 bg-emerald-400/10 text-emerald-300" : "border-amber-400/50 bg-amber-400/10 text-amber-300")}>
                      {d.status}
                    </span>
                    {d.status !== "confirmed" && (
                      <button data-testid={`confirm-btn-${d.name}`} onClick={() => confirm(d.name)}
                        className="flex shrink-0 items-center gap-1 rounded-md bg-emerald-500/15 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-500/25">
                        <ShieldCheck size={12} /> تأیید
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
