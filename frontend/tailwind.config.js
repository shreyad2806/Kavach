export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg:      "#0b0f1a",
        panel:   "#0d1526",
        panel2:  "#101a2e",
        deep:    "#0b0f1a",
        line:    "#1a2a45",
        line2:   "#223358",
        ink:     "#dce8ff",
        ink2:    "#7a9cc8",
        ink3:    "#3d5478",
        neon:    "#38bdf8",
        neondim: "#0ea5e9",
        amber:   "#fbbf24",
        danger:  "#f87171",
        dim:     "#1e3050",
        allow:   "#34d399",
        allowdim:"#059669",
      },
      fontFamily: {
        sans: ["Manrope", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        panel: "14px",
        btn:   "10px",
        tile:  "10px",
      },
      fontSize: {
        "card-title": ["14px", { fontWeight: "700", lineHeight: "1.3" }],
        "metric-label": ["12.5px", { fontWeight: "600", lineHeight: "1.4" }],
        "caption": ["11.5px", { lineHeight: "1.5" }],
      },
    },
  },
  safelist: [
    "bg-neon/5", "bg-neon/8", "bg-neon/10",
    "bg-danger/10", "bg-amber/10",
    "bg-allow/10",
    "border-neon/20", "border-neon/40",
    "border-danger/20", "border-amber/20",
    "border-allow/20",
    "text-allow",
  ],
  plugins: [],
};
