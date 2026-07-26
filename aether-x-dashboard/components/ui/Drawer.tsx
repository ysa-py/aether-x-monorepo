"use client";

import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import type { ReactNode } from "react";

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}

/** Side drawer for node inspection (used by the topology visualizer). */
export function Drawer({ open, onClose, title, children }: DrawerProps) {
  return (
    <AnimatePresence>
      {open && (
        <motion.aside
          key="drawer"
          initial={{ x: 360, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 360, opacity: 0 }}
          transition={{ type: "spring", stiffness: 320, damping: 34 }}
          className="glass fixed right-0 top-0 z-40 h-full w-80 overflow-y-auto rounded-l-2xl p-4"
          role="dialog"
          aria-label={title}
        >
          <header className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-noc-fg">{title}</h3>
            <button
              onClick={onClose}
              aria-label="close"
              className="rounded-md p-1 text-noc-muted hover:bg-noc-edge/40 hover:text-noc-fg"
            >
              <X size={16} />
            </button>
          </header>
          {children}
        </motion.aside>
      )}
    </AnimatePresence>
  );
}
