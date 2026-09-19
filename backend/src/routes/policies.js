import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

// Read-only. Policy mutation is intentionally NOT exposed.
router.get("/", (req, res) => proxyTo("/policies", req, res));

export default router;
