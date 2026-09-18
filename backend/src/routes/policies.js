import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

router.get("/", (req, res) => proxyTo("/policies", req, res));
router.post("/", (req, res) => proxyTo("/policies", req, res));

export default router;
