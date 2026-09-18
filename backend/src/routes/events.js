import { Router } from "express";
import { proxyTo } from "../proxy.js";

const router = Router();

router.get("/", (req, res) => proxyTo("/events", req, res));

export default router;
