export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg:      "#04120d",
        panel:   "#0a1f18",
        panel2:  "#0c261c",
        deep:    "#03140e",
        line:    "#12362a",
        line2:   "#17493a",
        ink:     "#e8fff4",
        ink2:    "#a7c9ba",
        ink3:    "#6d8f80",
        neon:    "#1fe98a",
        neondim: "#12b76a",
        amber:   "#ffc046",
        danger:  "#ff4d5e",
        dim:     "#4a6b5d",
      },
      fontFamily: {
        sans: ["Manrope", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        panel: "16px",
        btn:   "11px",
        tile:  "13px",
      },
      fontSize: {
        "card-title": ["14px", { fontWeight: "700", lineHeight: "1.3" }],
        "metric-label": ["12.5px", { fontWeight: "600", lineHeight: "1.4" }],
        "caption": ["11.5px", { lineHeight: "1.5" }],
      },
    },
  },
  plugins: [],
};
