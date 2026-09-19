import { useEffect } from "react";
import { CheckCircle, XCircle, AlertCircle, Info } from "lucide-react";

const ICONS = {
  success: <CheckCircle size={14} className="text-neon flex-shrink-0" />,
  error:   <XCircle size={14} className="text-danger flex-shrink-0" />,
  warning: <AlertCircle size={14} className="text-amber flex-shrink-0" />,
  info:    <Info size={14} className="text-ink2 flex-shrink-0" />,
};

function ToastItem({ toast, onDismiss }) {
  useEffect(() => {
    const t = setTimeout(() => onDismiss(toast.id), toast.duration ?? 3000);
    return () => clearTimeout(t);
  }, [toast.id, toast.duration, onDismiss]);

  return (
    <div
      className="flex items-center gap-2.5 rounded-tile bg-panel border border-line2 px-4 py-3 text-[12.5px] font-semibold text-ink shadow-lg"
      style={{ boxShadow: "0 4px 24px rgba(0,0,0,.5)" }}
      role="status"
      aria-live="polite"
    >
      {ICONS[toast.type || "info"]}
      <span>{toast.message}</span>
      <button
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
        className="ml-1 text-ink3 hover:text-ink transition-colors"
      >
        ×
      </button>
    </div>
  );
}

export function ToastStack({ toasts, onDismiss }) {
  if (!toasts.length) return null;
  return (
    <div
      className="fixed bottom-5 right-5 z-[60] flex flex-col gap-2 items-end"
      aria-label="Notifications"
    >
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}
