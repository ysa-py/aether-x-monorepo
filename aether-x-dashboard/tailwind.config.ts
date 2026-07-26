import type { Config } from "tailwindcss";

/**
 * Tailwind theme: industrial dark NOC aesthetic with RGB ambient accents.
 * Colors are stored as space-separated RGB triplets in CSS variables so they
 * compose with Tailwind's `rgb(var(--x) / <alpha>)` pattern, enabling dynamic
 * accent theming at runtime.
 */
const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
    "./hooks/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Industrial dark surfaces.
        noc: {
          bg: "rgb(var(--noc-bg) / <alpha-value>)",
          panel: "rgb(var(--noc-panel) / <alpha-value>)",
          edge: "rgb(var(--noc-edge) / <alpha-value>)",
          muted: "rgb(var(--noc-muted) / <alpha-value>)",
          fg: "rgb(var(--noc-fg) / <alpha-value>)",
        },
        accent: {
          cyan: "rgb(var(--accent-cyan) / <alpha-value>)",
          amber: "rgb(var(--accent-amber) / <alpha-value>)",
          crimson: "rgb(var(--accent-crimson) / <alpha-value>)",
          emerald: "rgb(var(--accent-emerald) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ["var(--font-vazirmatn)", "var(--font-geist)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "ui-monospace", "monospace"],
      },
      backdropBlur: {
        md: "12px",
      },
      boxShadow: {
        glow: "0 0 24px rgb(var(--accent-cyan) / 0.25)",
      },
      keyframes: {
        "pulse-soft": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.45" },
        },
      },
      animation: {
        "pulse-soft": "pulse-soft 2.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
