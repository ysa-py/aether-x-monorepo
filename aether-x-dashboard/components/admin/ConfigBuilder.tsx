"use client";

import { useState, useEffect, useCallback } from "react";
import { clsx } from "clsx";
import { Wand2, Copy, Check, Globe, Network, KeyRound, Sparkles, ChevronDown } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8080";

interface Transport {
  id: string;
  name: string;
  name_fa: string;
  family: string;
  needs_path: boolean;
  needs_host: boolean;
  needs_mode: boolean;
  modes?: string[];
  needs_service: boolean;
  description: string;
  newest: boolean;
  legacy: boolean;
}
interface Protocol { id: string; name: string; name_fa: string; }
interface Catalog { version: string; protocols: Protocol[]; transports: Transport[]; }
interface BuildResult {
  share_link: string;
  clash: string;
  singbox: string;
  base64: string;
  protocol: string;
  transport: string;
}
type Tab = "share" | "clash" | "singbox" | "base64";

// Built-in fallbacks so the panel is usable before /v1/transports responds.
const FALLBACK_PROTOCOLS: Protocol[] = [
  { id: "vless", name: "VLESS", name_fa: "VLESS" },
  { id: "vmess", name: "VMess", name_fa: "VMess" },
  { id: "trojan", name: "Trojan", name_fa: "تروجان" },
  { id: "shadowsocks", name: "Shadowsocks", name_fa: "شادوساکس" },
  { id: "hysteria2", name: "Hysteria 2", name_fa: "هیستریا ۲" },
  { id: "tuic", name: "TUIC v5", name_fa: "توئیک نسخه ۵" },
];
const FALLBACK_TRANSPORTS: Transport[] = [
  { id: "xhttp", name: "XHTTP", name_fa: "XHTTP", family: "http", needs_path: true, needs_host: true, needs_mode: true, modes: ["packet-up", "stream-up", "stream-one"], needs_service: false, description: "Newest Xray transport.", newest: true, legacy: false },
  { id: "ws", name: "WebSocket", name_fa: "وب‌سوکت", family: "websocket", needs_path: true, needs_host: true, needs_mode: false, needs_service: false, description: "Classic WebSocket.", newest: false, legacy: false },
  { id: "grpc", name: "gRPC", name_fa: "gRPC", family: "grpc", needs_path: false, needs_host: false, needs_mode: false, needs_service: true, description: "gRPC streams.", newest: false, legacy: false },
  { id: "tcp", name: "TCP", name_fa: "TCP", family: "stream", needs_path: false, needs_host: false, needs_mode: false, needs_service: false, description: "Raw TCP.", newest: false, legacy: false },
  { id: "quic", name: "QUIC", name_fa: "QUIC", family: "udp", needs_path: false, needs_host: true, needs_mode: false, needs_service: false, description: "Native QUIC for Hysteria2 and TUIC.", newest: true, legacy: false },
];

export function ConfigBuilder() {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [protocol, setProtocol] = useState("vless");
  const [transport, setTransport] = useState("xhttp");
  // Do not seed a production-looking form with a fictional endpoint. The
  // operator must supply reviewed connection material before it can be built.
  const [address, setAddress] = useState("");
  const [port, setPort] = useState(443);
  const [uuid, setUuid] = useState("");
  const [password, setPassword] = useState("");
  const [path, setPath] = useState("/sub");
  const [host, setHost] = useState("");
  const [sni, setSni] = useState("");
  const [serviceName, setServiceName] = useState("GunService");
  const [mode, setMode] = useState("packet-up");
  const [headerType, setHeaderType] = useState("none");
  const [upMbps, setUpMbps] = useState(100);
  const [downMbps, setDownMbps] = useState(200);
  const [congestionControl, setCongestionControl] = useState("bbr");
  const [udpRelayMode, setUdpRelayMode] = useState("native");

  const [result, setResult] = useState<BuildResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("share");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE}/v1/transports`)
      .then((r) => r.json())
      .then((c: Catalog) => { if (!cancelled) setCatalog(c); })
      .catch(() => { /* offline — keep built-in defaults */ });
    return () => { cancelled = true; };
  }, []);

  const isHysteria2 = protocol === "hysteria2";
  const isTuic = protocol === "tuic";
  const needsUUID = protocol === "vless" || protocol === "vmess" || isTuic;
  const needsPassword = protocol === "trojan" || protocol === "shadowsocks" || isHysteria2 || isTuic;
  const canBuild = address.trim() !== "" && port > 0
    && (!needsUUID || uuid.trim() !== "")
    && (!needsPassword || password.trim() !== "")
    && (!isHysteria2 || (upMbps > 0 && downMbps > 0));

  const build = useCallback(async () => {
    if (!canBuild) {
      setError("Provide a reviewed address and every required protocol credential before building.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/v1/admin/build-config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocol, transport, address, port, uuid, password,
          path, host, sni, service_name: serviceName, mode, header_type: headerType,
          up_mbps: upMbps, down_mbps: downMbps,
          congestion_control: congestionControl, udp_relay_mode: udpRelayMode,
        }),
      });
      if (!res.ok) throw new Error(`build failed: ${res.status}`);
      const data = (await res.json()) as BuildResult;
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "build failed");
    } finally {
      setBusy(false);
    }
  }, [protocol, transport, address, port, uuid, password, path, host, sni, serviceName, mode, headerType, upMbps, downMbps, congestionControl, udpRelayMode, canBuild]);

  const currentTransport = catalog?.transports.find((t) => t.id === transport);

  const copyShare = useCallback(async () => {
    if (!result?.share_link) return;
    try { await navigator.clipboard.writeText(result.share_link); } catch { /* best-effort */ }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }, [result?.share_link]);

  const tabBody = result
    ? ({ share: result.share_link, clash: result.clash, singbox: result.singbox, base64: result.base64 }[tab] ?? "")
    : "";

  return (
    <div className="min-h-screen bg-noc-bg p-4 md:p-8" dir="rtl">
      <style>{`
        @keyframes rgb-flow { 0%,100%{background-position:0% 50%} 50%{background-position:100% 50%} }
        .rgb-border{background:linear-gradient(135deg,rgb(0 240 255/.55),rgb(139 92 246/.55),rgb(236 72 153/.55),rgb(0 240 255/.55));background-size:300% 300%;animation:rgb-flow 6s ease infinite;box-shadow:0 0 18px rgb(139 92 246/.35)}
        .inp{width:100%;border-radius:0.375rem;border:1px solid rgb(var(--noc-edge) / .6);background:rgb(var(--noc-bg) / .5);padding:0.5rem 0.5rem;font-size:0.8rem;color:rgb(var(--noc-fg));outline:none}
        .inp:focus{border-color:rgb(var(--accent-cyan) / .7)}
      `}</style>

      <div className="mx-auto max-w-3xl space-y-4">
        {/* Header */}
        <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
          <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
            <h1 className="bg-gradient-to-r from-cyan-400 via-fuchsia-400 to-cyan-400 bg-clip-text text-2xl font-bold text-transparent">
              Config Builder
            </h1>
            <p className="mt-1 text-sm text-noc-muted">پنل ادمین — ساخت کانفیگ با تمام Transport Network ها (zero-code)</p>
          </div>
        </div>

        {/* Selector */}
        <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
          <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md space-y-4">
            {/* Protocol + Transport */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="پروتکل — Protocol" icon={<KeyRound size={14} />}>
                <select data-testid="protocol-select" value={protocol}
                  onChange={(e) => {
                    const nextProtocol = e.target.value;
                    setProtocol(nextProtocol);
                    if (nextProtocol === "hysteria2" || nextProtocol === "tuic") setTransport("quic");
                  }}
                  className="w-full rounded-md border border-noc-edge/60 bg-noc-bg/50 px-2 py-2 text-sm text-noc-fg outline-none focus:border-accent-cyan/70">
                  {(catalog?.protocols ?? FALLBACK_PROTOCOLS).map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </Field>
              <Field label="Transport Network" icon={<Network size={14} />}>
                <div className="relative">
                  <select data-testid="transport-select" value={transport}
                    onChange={(e) => setTransport(e.target.value)}
                    disabled={isHysteria2 || isTuic}
                    className="w-full appearance-none rounded-md border border-noc-edge/60 bg-noc-bg/50 px-2 py-2 pl-7 text-sm text-noc-fg outline-none focus:border-accent-cyan/70 disabled:cursor-not-allowed disabled:opacity-60">
                    {(catalog?.transports ?? FALLBACK_TRANSPORTS).map((t) => (
                      <option key={t.id} value={t.id}>{t.name_fa} ({t.id}){t.newest ? " ✨" : ""}</option>
                    ))}
                  </select>
                  <ChevronDown size={14} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-noc-muted" />
                </div>
              </Field>
            </div>

            {currentTransport && (
              <p data-testid="transport-desc" className="rounded-lg border border-noc-edge/40 bg-noc-bg/30 px-3 py-2 text-xs text-noc-muted">
                <span className={clsx("ml-1 font-semibold", currentTransport.newest ? "text-cyan-300" : currentTransport.legacy ? "text-noc-muted" : "text-fuchsia-300")}>
                  {currentTransport.newest ? "جدیدترین / Newest" : currentTransport.legacy ? "قدیمی / Legacy" : "پایدار / Stable"}
                </span>
                {currentTransport.description}
              </p>
            )}

            {/* Reviewed endpoint and protocol credentials. Native QUIC uses
                explicit Hysteria2/TUIC parameters; no fictional defaults are sent. */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <Field label="آدرس — Address" icon={<Globe size={14} />}>
                <input data-testid="address-input" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="operator node FQDN or IP" className="inp" dir="ltr" />
              </Field>
              <Field label="پورت — Port">
                <input data-testid="port-input" type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} className="inp" dir="ltr" />
              </Field>
              {needsUUID && (
                <Field label="UUID" icon={<KeyRound size={14} />}>
                  <input data-testid="uuid-input" value={uuid} onChange={(e) => setUuid(e.target.value)} className="inp" dir="ltr" />
                </Field>
              )}
              {needsPassword && (
                <Field label="Password" icon={<KeyRound size={14} />}>
                  <input data-testid="password-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="inp" dir="ltr" />
                </Field>
              )}
            </div>

            {!isHysteria2 && !isTuic ? (
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <Field label="Path"><input value={path} onChange={(e) => setPath(e.target.value)} className="inp" dir="ltr" /></Field>
                <Field label="Host"><input value={host} onChange={(e) => setHost(e.target.value)} className="inp" dir="ltr" /></Field>
                <Field label="SNI"><input value={sni} onChange={(e) => setSni(e.target.value)} className="inp" dir="ltr" /></Field>
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <Field label="SNI"><input value={sni} onChange={(e) => setSni(e.target.value)} placeholder="optional TLS server name" className="inp" dir="ltr" /></Field>
                {isHysteria2 ? (
                  <>
                    <Field label="Up Mbps"><input data-testid="up-mbps-input" type="number" min="1" value={upMbps} onChange={(e) => setUpMbps(Number(e.target.value))} className="inp" dir="ltr" /></Field>
                    <Field label="Down Mbps"><input data-testid="down-mbps-input" type="number" min="1" value={downMbps} onChange={(e) => setDownMbps(Number(e.target.value))} className="inp" dir="ltr" /></Field>
                  </>
                ) : (
                  <>
                    <Field label="Congestion control"><input value={congestionControl} onChange={(e) => setCongestionControl(e.target.value)} className="inp" dir="ltr" /></Field>
                    <Field label="UDP relay mode"><input value={udpRelayMode} onChange={(e) => setUdpRelayMode(e.target.value)} className="inp" dir="ltr" /></Field>
                  </>
                )}
              </div>
            )}

            {/* Transport-specific */}
            {currentTransport?.needs_service && (
              <Field label="gRPC serviceName"><input value={serviceName} onChange={(e) => setServiceName(e.target.value)} className="inp" dir="ltr" /></Field>
            )}
            {currentTransport?.needs_mode && (currentTransport.modes?.length ?? 0) > 0 && (
              <Field label={transport === "xhttp" ? "xHTTP Mode" : "Header / Obfs"}>
                <select data-testid="mode-select" value={transport === "xhttp" ? mode : headerType}
                  onChange={(e) => transport === "xhttp" ? setMode(e.target.value) : setHeaderType(e.target.value)}
                  className="w-full rounded-md border border-noc-edge/60 bg-noc-bg/50 px-2 py-2 text-sm text-noc-fg outline-none focus:border-accent-cyan/70">
                  {(currentTransport.modes ?? []).map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              </Field>
            )}

            <button data-testid="build-btn" onClick={build} disabled={busy || !canBuild}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500/25 via-fuchsia-500/25 to-cyan-500/25 px-4 py-3 text-sm font-bold text-cyan-200 transition-all hover:from-cyan-500/40 hover:to-fuchsia-500/40 disabled:opacity-50">
              <Wand2 size={16} /> {busy ? "در حال ساخت…" : "ساخت کانفیگ — Build Config"}
            </button>
            {error && <p data-testid="build-error" className="text-center text-xs text-red-400">{error}</p>}
          </div>
        </div>

        {/* Result */}
        {result && (
          <div data-testid="rgb-card" className="rgb-border rounded-2xl p-[2px]">
            <div className="rounded-2xl bg-noc-panel/90 p-6 backdrop-blur-md">
              <div className="mb-3 flex items-center justify-between">
                <span className="flex items-center gap-2 text-sm font-bold text-noc-fg">
                  <Sparkles size={16} className="text-cyan-300" /> خروجی — Output
                </span>
                <div className="flex flex-wrap gap-1">
                  {(["share", "clash", "singbox", "base64"] as Tab[]).map((t) => (
                    <button key={t} data-testid={`tab-${t}`} onClick={() => setTab(t)}
                      className={clsx("rounded-md px-2.5 py-1 text-xs", tab === t ? "bg-cyan-500/20 text-cyan-200" : "text-noc-muted hover:text-noc-fg")}>
                      {t === "share" ? "Share Link" : t === "singbox" ? "sing-box" : t === "base64" ? "Base64" : "Clash"}
                    </button>
                  ))}
                </div>
              </div>

              <pre data-testid="config-output" dir="ltr" className="max-h-80 overflow-auto rounded-lg border border-noc-edge/40 bg-noc-bg/60 p-3 font-mono text-[11px] leading-relaxed text-noc-fg whitespace-pre-wrap break-all">{tabBody}</pre>

              <div className="mt-3 flex items-center justify-between">
                <span data-testid="transport-badge" className="rounded-full border border-fuchsia-400/40 bg-fuchsia-400/10 px-3 py-0.5 text-xs text-fuchsia-300">
                  <Network size={11} className="mr-1 inline" /> {result.transport}
                </span>
                <button data-testid="copy-share" onClick={copyShare}
                  className="flex items-center gap-1.5 rounded-md border border-noc-edge/50 bg-noc-bg/40 px-3 py-1.5 text-xs text-noc-fg hover:border-cyan-400/60 hover:bg-cyan-400/10">
                  {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />} {copied ? "کپی شد!" : "کپی Share Link"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}

function Field({ label, icon, children }: { label: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center gap-1 text-xs text-noc-muted">
        {icon} {label}
      </span>
      {children}
    </label>
  );
}
