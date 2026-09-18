import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

router.get("/", (req, res) => proxyTo("/agents", req, res));
router.get("/:id", (req, res) => proxyTo(`/agents/${req.params.id}`, req, res));
router.post("/:id/isolate", (req, res) => proxyTo(`/agents/${req.params.id}/isolate`, req, res));
router.post("/:id/restore", (req, res) => proxyTo(`/agents/${req.params.id}/restore`, req, res));

export default router;
