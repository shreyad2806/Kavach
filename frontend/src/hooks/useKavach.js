/**
 * useKavach — single polling hook for all real backend data.
 *
 * Polls /agents, /events, /incidents, /dashboard every INTERVAL ms.
 * Uses a ref-based lock to prevent overlapping requests.
 * Stops when the component unmounts.
 *
 * Returns:
 *   agents        – live Shield identity list (5 agents)
 *   events        – Shield authorization audit events (chronological, newest last)
 *   incidents     – IncidentService list
 *   dashboard     – summary counts projection
 *   connected     – true once first successful fetch completes
 *   offline       – true once a fetch fails (stays true until next success)
 *   loading       – true only on the very first load
 *   refresh()     – trigger an immediate out-of-band poll
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { api } from "../api.js";

const INTERVAL_MS = 2000; // 2 s — lightweight, prevents overlapping requests

export function useKavach() {
  const [agents,    setAgents]    = useState([]);
  const [events,    setEvents]    = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [connected, setConnected] = useState(false);
  const [offline,   setOffline]   = useState(false);
  const [loading,   setLoading]   = useState(true);

  // Prevent overlapping fetches
  const inFlight = useRef(false);
  const unmounted = useRef(false);

  const poll = useCallback(async () => {
    if (inFlight.current || unmounted.current) return;
    inFlight.current = true;
    try {
      // Parallel fetch — all four in one round trip window
      const [agentsData, eventsData, incidentsData, dashboardData] = await Promise.all([
        api.getAgents(),
        api.getEvents(200),
        api.getIncidents(),
        api.getDashboard(),
      ]);
      if (unmounted.current) return;
      setAgents(agentsData);
      setEvents(eventsData);
      setIncidents(incidentsData);
      setDashboard(dashboardData);
      setConnected(true);
      setOffline(false);
      setLoading(false);
    } catch {
      if (unmounted.current) return;
      setOffline(true);
      setConnected(false);
      setLoading(false);
    } finally {
      inFlight.current = false;
    }
  }, []);

  // Kick off immediately then on interval
  useEffect(() => {
    unmounted.current = false;
    poll();
    const timer = setInterval(poll, INTERVAL_MS);
    return () => {
      unmounted.current = true;
      clearInterval(timer);
    };
  }, [poll]);

  return { agents, events, incidents, dashboard, connected, offline, loading, refresh: poll };
}
