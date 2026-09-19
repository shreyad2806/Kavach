import { Router } from "express";
import { proxyTo, WORKFLOW_START_TIMEOUT_MS } from "../proxy.js";

const router = Router();

// Workflow control plane -> unified Python backend (real WorkflowSupervisor).
router.post("/", (req, res) => proxyTo("/workflows", req, res));
router.get("/:id", (req, res) => proxyTo(`/workflows/${req.params.id}`, req, res));
// start is synchronous and runs the full 12-phase pipeline — needs a longer timeout
router.post("/:id/start", (req, res) =>
  proxyTo(`/workflows/${req.params.id}/start`, req, res, { timeoutMs: WORKFLOW_START_TIMEOUT_MS })
);
router.post("/:id/stop", (req, res) => proxyTo(`/workflows/${req.params.id}/stop`, req, res));
router.get("/:id/events", (req, res) => proxyTo(`/workflows/${req.params.id}/events`, req, res));

export default router;
