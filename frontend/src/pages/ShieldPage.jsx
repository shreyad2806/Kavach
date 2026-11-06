import { LandingPanel } from "../components/LandingPanel.jsx";

export function ShieldPage({
  agents = [],
  events = [],
  connected = false,
  error = "",
  onOpenRunWorkflow,
  onInspectEvent,
  onAgentSelect,
  selectedRequestId = null,
}) {
  return (
    <LandingPanel
      agents={agents}
      events={events}
      connected={connected}
      error={error}
      selectedRequestId={selectedRequestId}
      onOpenRunWorkflow={onOpenRunWorkflow}
      onInspectEvent={onInspectEvent}
      onAgentSelect={onAgentSelect}
    />
  );
}
