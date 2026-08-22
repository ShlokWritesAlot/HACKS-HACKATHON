import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#050811",
          surface: "#0b101d",
          elevated: "#111827",
          terminal: "#070c18",
          border: "rgba(6, 182, 212, 0.2)",
        },
        cyan: {
          500: "#06b6d4",
          400: "#22d3ee",
          950: "#083344",
        },
        emerald: {
          500: "#10b981",
          400: "#34d399",
          950: "#022c22",
        },
        amber: {
          500: "#f59e0b",
          400: "#fbbf24",
          950: "#451a03",
        },
        rose: {
          500: "#f43f5e",
          600: "#e11d48",
          950: "#4c0519",
        },
        // BhashaRakshak brand palette
        brand: {
          50: "#f0f4ff",
          100: "#dce6ff",
          200: "#b9ccff",
          300: "#86a5ff",
          400: "#4d73ff",
          500: "#2548ff",
          600: "#0d29f5",
          700: "#0a1ed8",
          800: "#0e1daf",
          900: "#111e89",
          950: "#0a1253",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
