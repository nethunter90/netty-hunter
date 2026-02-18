/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // Hacker aesthetic dark palette
        hack: {
          bg: "#0a0a0f",
          surface: "#0f0f1a",
          panel: "#141420",
          border: "#1e1e3f",
          muted: "#252540",
          text: "#c8c8e8",
          dim: "#6060a0",
          accent: "#00ff88",
          green: "#00cc66",
          cyan: "#00d4ff",
          blue: "#4488ff",
          purple: "#8844ff",
          red: "#ff3355",
          orange: "#ff8800",
          yellow: "#ffcc00",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Cascadia Code", "Fira Code", "Consolas", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      animation: {
        "pulse-green": "pulse-green 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scan-line 3s linear infinite",
        "matrix-rain": "matrix-rain 0.1s linear infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        "pulse-green": {
          "0%, 100%": { opacity: "1", color: "#00ff88" },
          "50%": { opacity: "0.5", color: "#00cc66" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "glow": {
          "from": { boxShadow: "0 0 5px #00ff8833" },
          "to": { boxShadow: "0 0 20px #00ff8866, 0 0 40px #00ff8833" },
        },
      },
    },
  },
  plugins: [],
};
