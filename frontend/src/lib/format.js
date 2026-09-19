// Relative time
export function relativeTime(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// Risk score → tone
export function riskTone(score) {
  if (score >= 80) return "danger";
  if (score >= 51) return "amber";
  if (score >= 21) return "neutral";
  return "neon";
}

// Risk score → hex color (for SVG charts)
export function riskColor(score) {
  if (score >= 80) return "#ff4d5e";
  if (score >= 51) return "#ffc046";
  return "#1fe98a";
}

// Agent state → badge tone
export function stateTone(state) {
  switch (state) {
    case "ACTIVE":      return "neon";
    case "QUARANTINED": return "danger";
    case "SUSPICIOUS":  return "amber";
    case "TERMINATED":  return "dim";
    default:            return "neutral";
  }
}

// Policy decision → tone
export function decisionTone(decision) {
  return decision === "ALLOW" ? "neon" : "danger";
}

// Incident severity → tone
export function severityTone(sev) {
  switch (sev) {
    case "CRITICAL": return "danger";
    case "HIGH":     return "danger";
    case "MEDIUM":   return "amber";
    case "LOW":      return "dim";
    default:         return "neutral";
  }
}

// Verdict → tone
export function verdictTone(verdict) {
  switch (verdict) {
    case "APPROVED":        return "neon";
    case "REVIEW_REQUIRED": return "amber";
    case "BLOCKED":         return "danger";
    default:                return "neutral";
  }
}

// Check status → tone (for auth pipeline nodes)
export function checkTone(status) {
  switch (status) {
    case "PASS":
    case "ALLOW":   return "neon";
    case "FAIL":
    case "DENY":
    case "BLOCK":   return "danger";
    default:        return "neutral";
  }
}

// Format a reason code for display (keep mono, uppercase)
export function fmtReasonCode(code) {
  return code.replace(/_/g, "_"); // already formatted, just pass through
}
