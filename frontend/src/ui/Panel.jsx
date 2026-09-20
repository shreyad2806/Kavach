// Panel — base card container
// tone: "default" | "deep" | "inset"
export function Panel({ children, className = "", tone = "default", style = {} }) {
  const bg = tone === "deep" ? "bg-deep" : tone === "inset" ? "bg-panel2" : "bg-panel";
  return (
    <div
      className={`panel-light border border-line rounded-panel ${bg} ${className}`}
      style={style}
    >
      {children}
    </div>
  );
}
