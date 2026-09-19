import { Router } from "express";
import { proxyTo, WORKFLOW_START_TIMEOUT_MS } from "../proxy.js";

const router = Router();

// Workflow control plane -> unified Python backend (real WorkflowSupervisor).
//
// Everything here is a thin pass-through.  Node holds no workflow state, no
// authorization logic and no security state — Shield owns all of that.
router.post("/", (req, res) => proxyTo("/workflows", req, res));

// Demo session control.  Declared BEFORE the parameterised /:id routes so the
// literal paths always win.  reset is a presentation control, not a security
// control: it can only release agents and forget the current session.
router.post("/demo/reset", (req, res) => proxyTo("/workflows/demo/reset", req, res));

// Attack simulation: the real KavachGuard denial + real quarantine + one real
// post-quarantine denial.  No verdict is synthesised on this side.
router.post("/simulation/attack", (req, res) =>
  proxyTo("/workflows/simulation/attack", req, res, { timeoutMs: WORKFLOW_START_TIMEOUT_MS })
);

router.get("/:id", (req, res) => proxyTo(`/workflows/${req.params.id}`, req, res));

// start returns immediately with RUNNING (the phases run on a backend worker
// thread); the extra headroom covers a cold worker start.
router.post("/:id/start", (req, res) =>
  proxyTo(`/workflows/${req.params.id}/start`, req, res, { timeoutMs: WORKFLOW_START_TIMEOUT_MS })
);
router.post("/:id/stop", (req, res) => proxyTo(`/workflows/${req.params.id}/stop`, req, res));
router.get("/:id/events", (req, res) => proxyTo(`/workflows/${req.params.id}/events`, req, res));

export default router;
