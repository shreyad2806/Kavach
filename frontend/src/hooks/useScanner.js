/**
 * useScanner — manages the full scan lifecycle.
 *
 * States: idle → submitting → polling → done | error
 * Polls GET /artifacts/:id every 3 s until a terminal status arrives.
 */
import { useState, useCallback, useRef, useEffect } from "react";
import { api } from "../api.js";

export function useScanner() {
  const [phase,      setPhase]      = useState("idle");
  const [artifactId, setArtifactId] = useState(null);
  const [result,     setResult]     = useState(null);
  const [error,      setError]      = useState("");
  const pollRef  = useRef(null);
  const attempts = useRef(0);

  // Cleanup on unmount
  useEffect(() => () => clearTimeout(pollRef.current), []);

  const poll = useCallback((id) => {
    attempts.current = 0;
    const tick = async () => {
      if (attempts.current >= 40) {           // 40 × 3 s = 2 min max
        setError("Scan timed out after 2 minutes.");
        setPhase("error");
        return;
      }
      attempts.current++;
      try {
        const data = await api.getArtifact(id);
        if (["APPROVED", "BLOCKED", "REVIEW_REQUIRED", "FAILED"].includes(data.status)) {
          setResult(data);
          setPhase("done");
          return;
        }
      } catch {
        // transient — keep polling
      }
      pollRef.current = setTimeout(tick, 3000);
    };
    pollRef.current = setTimeout(tick, 3000);
  }, []);

  const submit = useCallback(async (form) => {
    if (!form.source_url.trim()) {
      setError("Source URL is required.");
      return;
    }
    setError("");
    setResult(null);
    setArtifactId(null);
    setPhase("submitting");
    try {
      const { artifact_id } = await api.scanArtifact(form);
      setArtifactId(artifact_id);
      setPhase("polling");
      poll(artifact_id);
    } catch (e) {
      setError(e.message || "Scan submission failed.");
      setPhase("error");
    }
  }, [poll]);

  const reset = useCallback(() => {
    clearTimeout(pollRef.current);
    setPhase("idle");
    setResult(null);
    setArtifactId(null);
    setError("");
    attempts.current = 0;
  }, []);

  return { phase, artifactId, result, error, submit, reset };
}
