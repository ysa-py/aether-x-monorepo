"use client";

import { clsx } from "clsx";
import { KeyRound, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { MerkleTreeViewer } from "@/components/widgets/MerkleTreeViewer";
import { useAuditRoot, useVerifyToken } from "@/hooks/useQueries";
import { useI18n } from "@/lib/i18n";

export function TokenInspectorWidget() {
  const { t } = useI18n();
  const [token, setToken] = useState("");
  const [highlightLeaf, setHighlightLeaf] = useState(0);
  const verify = useVerifyToken();
  const audit = useAuditRoot();

  const result = verify.data;

  return (
    <Card title={t.tokens.title} icon={<KeyRound size={16} />}>
      <div className="flex gap-2">
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={t.tokens.tokenPlaceholder}
          data-testid="token-input"
          className="min-w-0 flex-1 rounded-md border border-noc-edge/60 bg-noc-bg/50 px-2 py-1.5 font-mono text-xs text-noc-fg outline-none focus:border-accent-cyan/70"
          aria-label={t.tokens.tokenPlaceholder}
        />
        <button
          data-testid="token-verify"
          onClick={() => token.trim() && verify.mutate(token.trim())}
          disabled={!token.trim() || verify.isPending}
          className="rounded-md bg-accent-emerald/15 px-3 py-1.5 text-xs text-accent-emerald hover:bg-accent-emerald/25 disabled:opacity-50"
        >
          {t.tokens.verify}
        </button>
      </div>

      {result && (
        <div className="flex flex-wrap gap-2 text-xs">
          <Pill ok={result.signature_valid} label={`${t.tokens.sigValid}: ${result.signature_valid}`} />
          <Pill ok={result.is_live} label={`${t.tokens.isLive}: ${result.is_live}`} />
        </div>
      )}

      <div className="rounded-lg border border-noc-edge/40 bg-noc-bg/30 p-2">
        <div className="mb-1 flex items-center justify-between text-xs text-noc-muted">
          <span>{t.tokens.merkleTree}</span>
          {audit.data && (
            <span className="font-mono">
              {t.tokens.root}: <span className="text-accent-cyan">{audit.data.merkle_root.slice(0, 12)}…</span>
              {" · "}#{audit.data.count}
            </span>
          )}
        </div>
        <MerkleTreeViewer
          count={audit.data?.count ?? 7}
          highlightLeaf={highlightLeaf}
          onSelectLeaf={setHighlightLeaf}
        />
      </div>
    </Card>
  );
}

function Pill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-full px-2 py-1",
        ok ? "bg-accent-emerald/15 text-accent-emerald" : "bg-accent-crimson/15 text-accent-crimson",
      )}
    >
      <ShieldCheck size={12} />
      {label}
    </span>
  );
}
