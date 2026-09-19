import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

// Workflow control plane -> unified Python backend (real WorkflowSupervisor).
router.post("/", (req, res) => proxyTo("/workflows", req, res));
router.get("/:id", (req, res) => proxyTo(`/workflows/${req.params.id}`, req, res));
router.post("/:id/start", (req, res) => proxyTo(`/workflows/${req.params.id}/start`, req, res));
router.post("/:id/stop", (req, res) => proxyTo(`/workflows/${req.params.id}/stop`, req, res));
router.get("/:id/events", (req, res) => proxyTo(`/workflows/${req.params.id}/events`, req, res));

export default router;
