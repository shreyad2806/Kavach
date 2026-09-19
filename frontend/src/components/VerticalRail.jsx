import { Plus, ArrowLeftRight } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";

export function VerticalRail({ onNew, onSwap }) {
  return (
    <Panel className="flex xl:flex-col flex-row items-center justify-center gap-3 p-3">
      <button
        onClick={onNew}
        aria-label="New scan"
        className="w-9 h-9 rounded-full border border-line2 flex items-center justify-center text-ink3 hover:text-neon hover:border-neon transition-colors"
      >
        <Plus size={15} />
      </button>
      <button
        onClick={onSwap}
        aria-label="Swap agent view"
        className="w-9 h-9 rounded-full border border-line2 flex items-center justify-center text-ink3 hover:text-ink hover:border-line transition-colors"
      >
        <ArrowLeftRight size={15} />
      </button>
    </Panel>
  );
}
