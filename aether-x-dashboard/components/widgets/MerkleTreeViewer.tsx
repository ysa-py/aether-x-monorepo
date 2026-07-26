"use client";

import { clsx } from "clsx";
import { useMemo } from "react";
import { useI18n } from "@/lib/i18n";

/**
 * Renders a compact binary Merkle tree derived from the leaf count, and
 * highlights the O(log n) inclusion path from the selected leaf to the root.
 * The node hashes are deterministic stand-ins (the live audit log commits the
 * real root via /v1/subscriptions/audit-root).
 */
export function MerkleTreeViewer({
  count,
  highlightLeaf,
  onSelectLeaf,
}: {
  count: number;
  highlightLeaf: number;
  onSelectLeaf: (i: number) => void;
}) {
  const { t } = useI18n();
  const leaves = Math.max(2, Math.min(count, 8));
  const depth = Math.ceil(Math.log2(leaves));

  /** Indices on the inclusion path from `highlightLeaf` up to the root. */
  const path = useMemo(() => {
    const set = new Set<number>();
    let idx = highlightLeaf % leaves;
    set.add(idx);
    for (let level = 0; level < depth; level++) {
      idx = Math.floor(idx / 2);
      set.add(idx + leaves * 100 + level); // unique key per level slot
    }
    return set;
  }, [highlightLeaf, leaves, depth]);

  const levels: number[][] = [];
  let width = leaves;
  while (width >= 1) {
    levels.push(Array.from({ length: width }, (_, i) => i));
    if (width === 1) break;
    width = Math.ceil(width / 2);
  }

  return (
    <div data-testid="merkle-tree" className="flex flex-col items-center gap-2">
      {levels
        .slice()
        .reverse()
        .map((row, levelIdx) => {
          const realLevel = levels.length - 1 - levelIdx;
          return (
            <div key={levelIdx} className="flex items-center justify-center gap-1.5">
              {row.map((nodeIdx) => {
                const isLeaf = realLevel === 0;
                const isRoot = realLevel === levels.length - 1 && levels.length > 1;
                const onPath =
                  (isLeaf && highlightLeaf % leaves === nodeIdx) ||
                  (!isLeaf && path.has(nodeIdx + leaves * 100 + realLevel));
                return (
                  <button
                    key={`${realLevel}-${nodeIdx}`}
                    onClick={() => isLeaf && onSelectLeaf(nodeIdx)}
                    disabled={!isLeaf}
                    title={isLeaf ? `${t.tokens.leaf} ${nodeIdx}` : isRoot ? t.tokens.root : ""}
                    className={clsx(
                      "h-4 w-4 rounded-sm transition-colors",
                      isRoot
                        ? "bg-accent-cyan"
                        : onPath
                          ? "bg-accent-emerald"
                          : isLeaf
                            ? "bg-noc-edge hover:bg-accent-amber/70"
                            : "bg-noc-edge/60",
                    )}
                  />
                );
              })}
            </div>
          );
        })}
      <p className="text-[10px] text-noc-muted">{t.tokens.proofPath} · O(log n)</p>
    </div>
  );
}
