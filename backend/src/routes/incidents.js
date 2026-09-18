import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

router.get("/", (req, res) => proxyTo("/incidents", req, res));
router.get("/:id", (req, res) => proxyTo(`/incidents/${req.params.id}`, req, res));

export default router;
