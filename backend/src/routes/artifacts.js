import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

router.post("/scan", (req, res) => proxyTo("/artifacts/scan", req, res));
router.get("/:id", (req, res) => proxyTo(`/artifacts/${req.params.id}`, req, res));

export default router;
