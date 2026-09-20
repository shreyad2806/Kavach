import { Router } from "express";
import { proxyTo, WORKFLOW_START_TIMEOUT_MS } from "../proxy.js";

const router = Router();

router.post("/scan", (req, res) => proxyTo("/artifacts/scan", req, res, { timeoutMs: WORKFLOW_START_TIMEOUT_MS }));
router.get("/:id", (req, res) => proxyTo(`/artifacts/${req.params.id}`, req, res));

export default router;
