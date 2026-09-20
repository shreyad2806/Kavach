// Button — tone: "neon" | "allow" | "danger" | "amber" | "dim" | "ghost" | "outline"
export function Button({
  children,
  tone = "neon",
  size = "md",
  disabled = false,
  onClick,
  className = "",
  title,
  "aria-label": ariaLabel,
  type = "button",
}) {
  const base =
    "inline-flex items-center justify-center gap-1.5 font-semibold rounded-btn transition-colors select-none";

  const sizes = {
    sm:   "px-3 py-1.5 text-[12px]",
    md:   "px-4 py-2 text-[13px]",
    lg:   "px-5 py-2.5 text-[13.5px]",
    icon: "w-8 h-8 p-0 text-[13px]",
  };

  const tones = {
    neon:    "bg-neon text-deep font-bold glow-neon hover:bg-neondim",
    allow:   "bg-neon text-deep font-bold glow-neon hover:bg-neondim",
    danger:  "bg-danger text-white font-bold glow-danger hover:bg-[#e63d4d]",
    amber:   "bg-amber text-deep font-bold hover:bg-[#e6ac3d]",
    dim:     "bg-line2 text-ink2 hover:bg-line",
    ghost:   "bg-transparent text-ink2 hover:text-ink hover:bg-line",
    outline: "bg-transparent border border-line2 text-ink2 hover:border-neon hover:text-neon",
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-label={ariaLabel}
      className={`${base} ${sizes[size]} ${tones[tone] ?? tones.neon} ${disabled ? "opacity-40 cursor-not-allowed pointer-events-none" : ""} ${className}`}
    >
      {children}
    </button>
  );
}
