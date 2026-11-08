const css = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg: css("app-bg"), panel: css("surface"), panel2: css("surface-raised"),
        deep: css("app-bg"), line: css("line"), line2: css("line-strong"),
        ink: css("text-strong"), ink2: css("text"), ink3: css("text-muted"),
        neon: css("accent"), neondim: css("accent-strong"),
        amber: "#d99b36", danger: "#dc625f", dim: css("line-strong"),
        allow: "#249b76", allowdim: "#187c60",
        cyan: {
          300: css("accent-soft"), 400: css("accent"), 500: css("accent-strong"),
          600: css("accent-strong"),
        },
        sky: { 300: css("accent-soft"), 400: css("accent"), 500: css("accent-strong") },
        slate: {
          100: css("text-strong"), 200: css("text-strong"), 300: css("text"),
          400: css("text-muted"), 500: css("text-muted"), 600: css("text-faint"),
          700: css("line-strong"), 800: css("surface-raised"), 900: css("surface"),
          950: css("app-bg"),
        },
      },
      fontFamily: {
        sans: ["Manrope", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      borderRadius: { panel: "14px", btn: "10px", tile: "10px" },
      fontSize: {
        "card-title": ["14px", { fontWeight: "700", lineHeight: "1.3" }],
        "metric-label": ["12.5px", { fontWeight: "600", lineHeight: "1.4" }],
        caption: ["11.5px", { lineHeight: "1.5" }],
      },
    },
  },
  safelist: [
    "bg-neon/5", "bg-neon/8", "bg-neon/10", "bg-danger/10", "bg-amber/10",
    "bg-allow/10", "border-neon/20", "border-neon/40", "border-danger/20",
    "border-amber/20", "border-allow/20", "text-allow",
  ],
  plugins: [],
};
