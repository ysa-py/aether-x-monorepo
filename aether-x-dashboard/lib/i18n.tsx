"use client";

import { createContext, useContext, useEffect, useMemo, useState } from "react";

export type Locale = "en" | "fa";
export type Dir = "ltr" | "rtl";

/** Deep dictionary type derived from the English keys. */
const en = {
  title: "Aether-X NOC",
  subtitle: "Nation-state censorship circumvention — control plane",
  status: {
    connected: "Connected",
    reconnecting: "Reconnecting",
    offline: "Offline",
  },
  nav: {
    cores: "Cores",
    tokens: "Tokens",
    routing: "Routing",
    dpi: "DPI Simulator",
  },
  topology: {
    title: "Topology",
    controlPlane: "Control Plane",
    supervisor: "Supervisor",
    proxyCores: "Proxy Cores",
    ispGateways: "ISP Gateways",
    inspect: "Inspect",
  },
  cores: {
    title: "Core Supervisor",
    empty: "No supervised cores.",
    hotSwap: "Hot-swap",
    protocol: "Protocol",
    restarts: "Restarts",
    status: "Status",
  },
  tokens: {
    title: "Anti-Forgery Inspector",
    verify: "Verify",
    issue: "Issue",
    tokenPlaceholder: "paste Ed25519 token…",
    sigValid: "Signature valid",
    isLive: "Live",
    merkleTree: "Merkle Audit Tree",
    auditSeq: "Audit #",
    root: "Root",
    leaf: "Leaf",
    proofPath: "Inclusion path",
  },
  routing: {
    title: "Route Tester",
    domainPlaceholder: "domain or IP…",
    query: "Query",
    decision: "Decision",
    validatedBy: "Validated by",
  },
  dpi: {
    title: "DPI Attack Simulator",
    injectRst: "Inject RST",
    dropPackets: "Drop packets",
    blockTls: "Block ClientHello",
    run: "Run simulation",
    cleared: "Cleared",
  },
  language: "فارسی",
};

export type Dictionary = typeof en;

const fa: Dictionary = {
  title: "مرکز عملیات اِثِر-ایکس",
  subtitle: "دورزدن سانسور کشوری — صفحهٔ کنترل",
  status: {
    connected: "متصل",
    reconnecting: "در حال اتصال",
    offline: "آفلاین",
  },
  nav: {
    cores: "هسته‌ها",
    tokens: "توکن‌ها",
    routing: "مسیریابی",
    dpi: "شبیه‌ساز DPI",
  },
  topology: {
    title: "توپولوژی",
    controlPlane: "صفحهٔ کنترل",
    supervisor: "نظارت‌گر",
    proxyCores: "هسته‌های پراکسی",
    ispGateways: "دروازه‌های ISP",
    inspect: "بازرسی",
  },
  cores: {
    title: "نظارت‌گر هسته",
    empty: "هیچ هسته‌ای نظارت نمی‌شود.",
    hotSwap: "تعویض زنده",
    protocol: "پروتکل",
    restarts: "راه‌اندازی‌ها",
    status: "وضعیت",
  },
  tokens: {
    title: "بازرس ضدتقلن",
    verify: "تأیید",
    issue: "صدور",
    tokenPlaceholder: "توکن Ed25519 را بچسبانید…",
    sigValid: "امضا معتبر",
    isLive: "فعّال",
    merkleTree: "درخت حسابرسی مرکل",
    auditSeq: "حسابرسی #",
    root: "ریشه",
    leaf: "برگ",
    proofPath: "مسیر اثبات",
  },
  routing: {
    title: "آزمونگر مسیر",
    domainPlaceholder: "دامنه یا IP…",
    query: "پرس‌وجو",
    decision: "تصمیم",
    validatedBy: "تأییدشده توسط",
  },
  dpi: {
    title: "شبیه‌ساز حملهٔ DPI",
    injectRst: "تزریق RST",
    dropPackets: "ریختن بسته‌ها",
    blockTls: "انسداد ClientHello",
    run: "اجرای شبیه‌سازی",
    cleared: "پاک شد",
  },
  language: "English",
};

const dictionaries: Record<Locale, Dictionary> = { en, fa };

export function dirOf(locale: Locale): Dir {
  return locale === "fa" ? "rtl" : "ltr";
}

interface I18nValue {
  locale: Locale;
  dir: Dir;
  t: Dictionary;
  toggle: () => void;
}

const I18nContext = createContext<I18nValue | null>(null);

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocale] = useState<Locale>("en");

  // Apply <html dir> + lang without layout shift (runs before paint via useLayoutEffect equivalent).
  useEffect(() => {
    const dir = dirOf(locale);
    document.documentElement.dir = dir;
    document.documentElement.lang = locale;
  }, [locale]);

  const value = useMemo<I18nValue>(
    () => ({
      locale,
      dir: dirOf(locale),
      t: dictionaries[locale],
      toggle: () => setLocale((p) => (p === "en" ? "fa" : "en")),
    }),
    [locale],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}
