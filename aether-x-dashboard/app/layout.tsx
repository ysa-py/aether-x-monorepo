import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Aether-X NOC",
  description: "Nation-state censorship circumvention — control plane",
};

export const viewport: Viewport = {
  themeColor: "#06080e",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // dir/lang are set client-side by I18nProvider (zero CLS).
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <body className="min-h-screen bg-noc-bg text-noc-fg antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
