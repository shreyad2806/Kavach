import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

router.get("/", (req, res) => proxyTo("/dashboard", req, res));

export default router;
