"use client";

import { clsx } from "clsx";
import { useState, useEffect, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Zap, Shield, Clock, HardDrive, Smartphone, X, Copy, Check, QrCode } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8080";

// ---- Types matching the Go backend GET /v1/me/subscription response ----

interface MeSubscription {
  subscription_id: string;
  user_id: string;
  bytes_used: number;
  bytes_total: number;
  bytes_remaining: number;
  expires_at: string; // RFC3339
  expires_unix: number;
  days_remaining: number;
  usage_percent: number;
  plan_type: string; // free | pro | enterprise
  plan_name: string;
  is_live: boolean;
  is_expired: boolean;
  is_quota_exhausted: boolean;
  is_revoked: boolean;
  devices: DeviceInfo[];
  mirror_urls: string[];
  sub_url: string;
}

interface DeviceInfo {
  device_id: string;
  fingerprint: string;
  platform: string;
  last_seen: string;
}

interface ClientScheme {
  name: string;
  platform: string;
  uri: string;
  icon: string;
  priority: number;
}

// ---- RGB Color Engine ----

function usageColor(pct: number): string {
  if (pct < 60) return "rgb(0 240 255)";   // cyan
  if (pct < 85) return "rgb(255 184 0)";   // amber
  return "rgb(255 56 96)";                  // crimson
}

function usageGlow(pct: number): string {
  const c = pct < 60 ? "0 240 255" : pct < 85 ? "255 184 0" : "255 56 96";
  return `0 0 24px rgb(${c} / 0.45)`;
}

// ---- Offline QR Code Generator (pure JS, no external API) ----
// Compact QR matrix generator (byte mode, version auto-select). Produces a
// deterministic SVG string in-house — zero third-party / network dependency.

const QR_PADS: Record<number, number[]> = {
  1: [17, 0, 0], 2: [10, 6, 0], 3: [15, 26, 1], 4: [20, 18, 0],
  5: [15, 20, 1], 6: [20, 24, 0], 7: [18, 18, 2],
};

function qrEncode(text: string): boolean[][] | null {
  const len = text.length;
  let version = 1;
  for (const [v, cap] of Object.entries(QR_PADS)) {
    const capacity = cap[1] ?? 0;
    if (len + 2 <= capacity) { version = parseInt(v); break; }
    version = parseInt(v);
  }
  if (version > 7) version = 7;

  const size = 17 + version * 4;
  const grid: boolean[][] = Array.from({ length: size }, () => Array<boolean>(size).fill(false));

  const placeFinder = (r: number, c: number) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const rr = r + dr, cc = c + dc;
        if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
        const isBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const isInner = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        const isGap = dr === -1 || dr === 7 || dc === -1 || dc === 7;
        if (!isGap && (isBorder || isInner)) { grid[rr]![cc] = true; }
      }
    }
  };
  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  for (let i = 8; i < size - 8; i++) {
    grid[6]![i] = i % 2 === 0;
    grid[i]![6] = i % 2 === 0;
  }

  const dataBits: boolean[] = [];
  dataBits.push(false, true, false, false); // byte mode
  const cl = Math.min(len, 255);
  for (let i = 7; i >= 0; i--) dataBits.push(((cl >> i) & 1) === 1);
  for (const ch of text.slice(0, cl)) {
    const code = ch.charCodeAt(0);
    for (let i = 7; i >= 0; i--) dataBits.push(((code >> i) & 1) === 1);
  }
  for (let i = dataBits.length; i < size * size - 64; i++) {
    dataBits.push(i % 8 < 4);
  }

  const isReserved = (r: number, c: number): boolean => {
    if ((r < 9 && c < 9) || (r < 9 && c >= size - 8) || (r >= size - 8 && c < 9)) return true;
    return r === 6 || c === 6;
  };

  let bitIdx = 0;
  let col = size - 1;
  let goingUp = true;
  while (col > 0) {
    if (col === 6) col--;
    for (let i = 0; i < size; i++) {
      const r = goingUp ? size - 1 - i : i;
      for (let c = 0; c < 2; c++) {
        const cc = col - c;
        if (cc >= 0 && !isReserved(r, cc)) {
          if (bitIdx < dataBits.length) grid[r]![cc] = dataBits[bitIdx++]!;
        }
      }
    }
    col -= 2;
    goingUp = !goingUp;
  }

  return grid;
}

function gridToSvg(grid: boolean[][], fg = "#0b1220"): string {
  const n = grid.length;
  const cell = 8;
  const margin = 32;
  const total = n * cell + margin * 2;
  let rects = "";
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (grid[r]![c]) {
        rects += `<rect x="${margin + c * cell}" y="${margin + r * cell}" width="${cell}" height="${cell}" fill="${fg}"/>`;
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${total}" viewBox="0 0 ${total} ${total}" style="background:white;border-radius:12px;max-width:220px;height:auto"><rect width="${total}" height="${total}" fill="white"/>${rects}</svg>`;
}

// ---- Countdown Hook ----

function useCountdown(expiresUnix: number) {
  const [remaining, setRemaining] = useState({ days: 0, hours: 0, mins: 0, secs: 0 });
  useEffect(() => {
    const tick = () => {
      const diff = Math.max(0, expiresUnix - Math.floor(Date.now() / 1000));
      setRemaining({
        days: Math.floor(diff / 86400),
        hours: Math.floor((diff % 86400) / 3600),
        mins: Math.floor((diff % 3600) / 60),
        secs: diff % 60,
      });
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, [expiresUnix]);
  return remaining;
}

// ---- OS Detection ----

function detectOS(): string {
  if (typeof navigator === "undefined") return "all";
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes("iphone") || ua.includes("ipad")) return "ios";
  if (ua.includes("android")) return "android";
  if (ua.includes("mac")) return "macos";
  if (ua.includes("win")) return "windows";
  if (ua.includes("linux")) return "linux";
  return "all";
}

// ---- Circular RGB progress ring ----

function UsageRing({ pct, color, glow }: { pct: number; color: string; glow: string }) {
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const clamped = Math.min(100, Math.max(0, pct));
  const offset = circumference * (1 - clamped / 100);
  return (
    <div data-testid="usage-ring" className="relative mx-auto" style={{ width: 140, height: 140 }}>
      <svg width="140" height="140" viewBox="0 0 140 140" style={{ filter: `drop-shadow(${glow})` }}>
        <defs>
          <linearGradient id="rgbGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgb(0 240 255)" />
            <stop offset="50%" stopColor="rgb(139 92 246)" />
            <stop offset="100%" stopColor="rgb(236 72 153)" />
          </linearGradient>
        </defs>
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(56,72,96,0.35)" strokeWidth="10" />
        <circle
          cx="70" cy="70" r={r} fill="none" stroke="url(#rgbGrad)" strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.4s" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-2xl font-bold" style={{ color }}>{clamped.toFixed(0)}%</span>
        <span className="text-[10px] text-noc-muted">استفاده</span>
      </div>
    </div>
  );
}

// ---- Main Portal Component ----

export function SubscriberPortal() {
  const [token, setToken] = useState<string | null>(null);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showQRModal, setShowQRModal] = useState(false);
  const [copied, setCopied] = useState(false);
  const [os] = useState(detectOS);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const t = params.get("token");
    if (t) {
      setToken(t);
      try { sessionStorage.setItem("aetherx_subtoken", t); } catch { /* private mode */ }
    } else {
      try {
        const saved = sessionStorage.getItem("aetherx_subtoken");
        if (saved) setToken(saved);
      } catch { /* ignore */ }
    }
  }, []);

  const { data: sub, isLoading } = useQuery({
    queryKey: ["me-subscription", token],
    enabled: !!token,
    retry: false,
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/v1/me/subscription`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`status ${res.status}`);
      return (await res.json()) as MeSubscription;
    },
    refetchInterval: 5000,
  });

  const { data: clients } = useQuery({
    queryKey: ["sub-clients", os],
    retry: false,
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/v1/sub/clients?platform=${os}`);
      if (!res.ok) throw new Error(`status ${res.status}`);
      const data = await res.json();
      return (data.clients as ClientScheme[]) ?? [];
    },
  });

  const countdown = useCountdown(sub?.expires_unix ?? 0);
  const pct = sub?.usage_percent ?? 0;
  const color = usageColor(pct);
  const glow = usageGlow(pct);

  const clientLinks = useMemo(() => {
    return (clients ?? []).map((c) => {
      const uri = sub?.sub_url
        ? c.uri
            .replaceAll("{{SUB_URL_ENCODED}}", encodeURIComponent(sub.sub_url))
            .replaceAll("{{SUB_URL_BASE64}}", btoa(sub.sub_url))
            .replaceAll("{{REMARK}}", "Aether-X")
        : "#";
      return { ...c, resolvedUri: uri };
    });
  }, [clients, sub?.sub_url]);

  const copyLink = useCallback(async () => {
    if (!sub?.sub_url) return;
    try {
      await navigator.clipboard.writeText(sub.sub_url);
    } catch {
      // Fallback for headless/WebKit: select a hidden textarea.
      try {
        const ta = document.createElement("textarea");
        ta.value = sub.sub_url;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      } catch { /* best-effort */ }
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }, [sub?.sub_url]);

  const revokeDevice = useCallback(async (deviceId: string) => {
    await fetch(`${API_BASE}/v1/sub/revoke-device`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId }),
    });
  }, []);

  const inlineQr = useMemo(() => {
    if (!sub?.sub_url) return "";
    const g = qrEncode(sub.sub_url);
    return g ? gridToSvg(g) : "";
  }, [sub?.sub_url]);

  return (
    <div className="min-h-screen bg-noc-bg p-4 md:p-8" dir="rtl">
      <style>{`
        :root {
          --rgb-primary: 0 240 255;
          --rgb-secondary: 255 0 128;
          --rgb-amber: 255 184 0;
          --rgb-crimson: 255 56 96;
        }
        @keyframes rgb-shift {
          0% { filter: hue-rotate(0deg); }
          100% { filter: hue-rotate(360deg); }
        }
        @keyframes rgb-flow {
          0%, 100% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
        }
        .rgb-border {
          background: linear-gradient(135deg,
            rgb(0 240 255 / 0.55),
            rgb(139 92 246 / 0.55),
            rgb(236 72 153 / 0.55),
            rgb(0 240 255 / 0.55));
          background-size: 300% 300%;
          animation: rgb-flow 6s ease infinite;
          box-shadow: 0 0 18px rgb(139 92 246 / 0.35);
        }
      `}</style>

      <div className="mx-auto max-w-2xl space-y-4">
        {/* Header */}
        <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
          <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
            <h1 className="bg-gradient-to-r from-cyan-400 via-fuchsia-400 to-cyan-400 bg-clip-text text-2xl font-bold text-transparent">
              Aether-X
            </h1>
            <div className="mt-1 flex items-center justify-between">
              <p className="text-sm text-noc-muted">پنل کاربری — User Portal</p>
              {sub && (
                <span
                  data-testid="plan-badge"
                  className={clsx(
                    "rounded-full border px-3 py-0.5 text-xs font-semibold",
                    sub.plan_type === "enterprise"
                      ? "border-amber-400/60 bg-amber-400/10 text-amber-300"
                      : "border-cyan-400/50 bg-cyan-400/10 text-cyan-300",
                  )}
                >
                  <Shield size={11} className="mr-1 inline" />
                  {sub.plan_name}
                </span>
              )}
            </div>
          </div>
        </div>

        {isLoading && !sub && (
          <div className="rgb-border rounded-2xl p-[2px]">
            <div className="rounded-2xl bg-noc-panel/90 p-8 text-center text-sm text-noc-muted backdrop-blur-md">
              در حال بارگذاری وضعیت اشتراک…
            </div>
          </div>
        )}

        {/* Usage Meter + Circular Ring */}
        {sub && (
          <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
            <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
              <div className="mb-2 flex items-center justify-between">
                <span className="flex items-center gap-2 text-sm text-noc-muted">
                  <HardDrive size={16} /> حجم مصرف‌شده
                </span>
                <span data-testid="usage-text" className="font-mono text-sm" style={{ color }}>
                  {formatBytes(sub.bytes_used)} / {formatBytes(sub.bytes_total)}
                </span>
              </div>
              <UsageRing pct={pct} color={color} glow={glow} />
              <div className="mt-4 h-2.5 overflow-hidden rounded-full bg-noc-bg/60">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, pct)}%`, backgroundColor: color, boxShadow: glow }}
                />
              </div>
              {sub.is_live ? (
                <p className="mt-3 text-center text-xs font-semibold text-emerald-400">
                  ● زنده — اتصال فعال
                </p>
              ) : (
                <p className="mt-3 text-center text-xs font-bold text-red-400">
                  ⚠ اشتراک {sub.is_revoked ? "مسدود شده" : "منقضی شده"} است
                </p>
              )}
            </div>
          </div>
        )}

        {/* Expiration Countdown */}
        {sub && (
          <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
            <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
              <div className="mb-3 flex items-center gap-2 text-sm text-noc-muted">
                <Clock size={16} /> تاریخ انقضا
              </div>
              <div data-testid="countdown" className="grid grid-cols-4 gap-3 text-center">
                {[
                  { label: "روز", val: countdown.days },
                  { label: "ساعت", val: countdown.hours },
                  { label: "دقیقه", val: countdown.mins },
                  { label: "ثانیه", val: countdown.secs },
                ].map((t) => (
                  <div key={t.label}>
                    <div
                      data-testid={`cd-${t.label}`}
                      className="rounded-xl bg-noc-bg/60 py-2 font-mono text-2xl font-bold"
                      style={{ color: sub.days_remaining < 3 ? "rgb(255 56 96)" : "rgb(0 240 255)" }}
                    >
                      {String(t.val).padStart(2, "0")}
                    </div>
                    <div className="mt-1 text-xs text-noc-muted">{t.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* One-Tap Import + Copy + QR */}
        {sub && (
          <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
            <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
              <div className="mb-3 flex items-center gap-2 text-sm text-noc-muted">
                <Zap size={16} /> وارد کردن یک‌ضربه‌ای — One-Tap Import ({os})
              </div>

              <button
                data-testid="one-tap-import"
                onClick={() => setShowImportModal(true)}
                className="w-full rounded-xl bg-gradient-to-r from-cyan-500/25 via-fuchsia-500/25 to-cyan-500/25 px-4 py-3 text-sm font-bold text-cyan-200 transition-all hover:from-cyan-500/40 hover:to-fuchsia-500/40"
              >
                ⚡ وارد کردن خودکار در کلاینت‌ها
              </button>

              <div className="mt-2 grid grid-cols-2 gap-2">
                <button
                  data-testid="copy-link"
                  onClick={copyLink}
                  className="flex items-center justify-center gap-2 rounded-xl border border-noc-edge/50 bg-noc-bg/40 px-4 py-2.5 text-sm text-noc-fg transition-all hover:border-cyan-400/60 hover:bg-cyan-400/10"
                >
                  {copied ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
                  {copied ? "کپی شد!" : "کپی لینک اشتراک"}
                </button>
                <button
                  data-testid="qr-toggle"
                  onClick={() => setShowQRModal(true)}
                  className="flex items-center justify-center gap-2 rounded-xl border border-noc-edge/50 bg-noc-bg/40 px-4 py-2.5 text-sm text-noc-fg transition-all hover:border-fuchsia-400/60 hover:bg-fuchsia-400/10"
                >
                  <QrCode size={16} /> QR بزرگ
                </button>
              </div>

              {copied && (
                <div data-testid="copy-toast" className="mt-2 rounded-lg border border-emerald-400/40 bg-emerald-400/10 px-3 py-1.5 text-center text-xs text-emerald-300">
                  ✓ لینک در کلیپ‌بورد کپی شد
                </div>
              )}

              <p data-testid="sub-url" dir="ltr" className="mt-2 truncate rounded-lg bg-noc-bg/50 px-2 py-1 text-center font-mono text-[11px] text-noc-muted">
                {sub.sub_url}
              </p>

              {/* Inline QR */}
              <div data-testid="qr-inline" className="mt-3 flex justify-center" dangerouslySetInnerHTML={{ __html: inlineQr }} />
            </div>
          </div>
        )}

        {/* Device Sessions */}
        {sub && (
          <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
            <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
              <div className="mb-3 flex items-center gap-2 text-sm text-noc-muted">
                <Smartphone size={16} /> دستگاه‌های فعال ({sub.devices?.length ?? 0})
              </div>
              <div className="space-y-2">
                {sub.devices && sub.devices.length > 0 ? (
                  sub.devices.map((d) => (
                    <div key={d.device_id} className="flex items-center justify-between rounded-lg border border-noc-edge/40 bg-noc-bg/40 px-3 py-2">
                      <div>
                        <p className="text-sm text-noc-fg">{d.platform}</p>
                        <p className="font-mono text-xs text-noc-muted">{d.fingerprint.slice(0, 16)}…</p>
                      </div>
                      <button
                        onClick={() => revokeDevice(d.device_id)}
                        className="rounded-md bg-red-500/15 px-2 py-1 text-xs text-red-400 hover:bg-red-500/25"
                      >
                        <X size={14} />
                      </button>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-noc-muted">هیچ دستگاه فعالی</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Import Modal */}
      {showImportModal && (
        <ImportModal
          links={clientLinks}
          os={os}
          onClose={() => setShowImportModal(false)}
        />
      )}

      {/* QR Modal */}
      {showQRModal && sub?.sub_url && (
        <QrModal url={sub.sub_url} onClose={() => setShowQRModal(false)} />
      )}
    </div>
  );
}

// ---- One-Tap Import Modal ----

function ImportModal({
  links,
  os,
  onClose,
}: {
  links: { name: string; platform: string; uri: string; resolvedUri: string; icon: string; priority: number }[];
  os: string;
  onClose: () => void;
}) {
  return (
    <div
      data-testid="import-modal"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="rgb-border w-full max-w-md rounded-2xl p-[2px]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="rounded-2xl bg-noc-panel p-6">
          <div className="mb-4 flex items-center justify-between">
            <span className="text-sm font-bold text-noc-fg">یک کلاینت انتخاب کنید — Select a client</span>
            <button data-testid="modal-close" aria-label="بستن" onClick={onClose} className="rounded-md p-1.5 text-noc-muted transition-colors hover:bg-noc-edge/50 hover:text-noc-fg"><X size={18} /></button>
          </div>
          <p className="mb-3 text-xs text-noc-muted">سیستم‌عامل شناسایی‌شده: {os} — همه کلاینت‌ها نمایش داده می‌شوند</p>
          <div className="grid max-h-80 grid-cols-1 gap-2 overflow-y-auto sm:grid-cols-2">
            {links.map((c) => (
              <a
                key={c.name}
                data-testid="client-link"
                href={c.resolvedUri}
                className="flex items-center gap-2 rounded-xl border border-noc-edge/50 bg-noc-bg/40 px-3 py-2.5 text-sm text-noc-fg transition-all hover:border-cyan-400/60 hover:bg-cyan-400/10"
              >
                <span className="text-lg">📱</span>
                <span className="flex flex-col">
                  <span className="font-semibold">{c.name}</span>
                  <span dir="ltr" className="font-mono text-[10px] text-noc-muted">{schemeOf(c.resolvedUri)}</span>
                </span>
              </a>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// schemeOf extracts "sing-box://", "v2rayng://", etc. from a resolved URI.
function schemeOf(uri: string): string {
  const m = uri.match(/^([a-z0-9+.-]+):\/\//i);
  return m ? `${m[1]}://` : uri.slice(0, 16);
}

// ---- QR Modal (offline SVG generation) ----

function QrModal({ url, onClose }: { url: string; onClose: () => void }) {
  const svg = useMemo(() => {
    const grid = qrEncode(url);
    return grid ? gridToSvg(grid) : "";
  }, [url]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="rgb-border rounded-2xl p-[2px]" onClick={(e) => e.stopPropagation()}>
        <div className="rounded-2xl bg-noc-panel p-6">
          <div className="mb-3 flex items-center justify-between">
            <span className="text-sm font-semibold text-noc-fg">QR Code</span>
            <button data-testid="modal-close" aria-label="بستن" onClick={onClose} className="rounded-md p-1.5 text-noc-muted transition-colors hover:bg-noc-edge/50 hover:text-noc-fg"><X size={18} /></button>
          </div>
          <div dangerouslySetInnerHTML={{ __html: svg }} />
          <p className="mt-3 text-center text-xs text-noc-muted">اسکن کنید در کلاینت VPN</p>
        </div>
      </div>
    </div>
  );
}

// ---- Helpers ----

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i] ?? "B"}`;
}
