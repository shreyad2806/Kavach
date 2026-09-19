import "dotenv/config";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { apiKeyAuth } from "./middleware/auth.js";
import { proxyTo } from "./proxy.js";
import agentsRouter from "./routes/agents.js";
import eventsRouter from "./routes/events.js";
import dashboardRouter from "./routes/dashboard.js";
import incidentsRouter from "./routes/incidents.js";
import policiesRouter from "./routes/policies.js";
import artifactsRouter from "./routes/artifacts.js";
import workflowsRouter from "./routes/workflows.js";

const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:5173" }));
app.use(express.json());
app.use(rateLimit({
  windowMs: 60_000,
  max: 500,
  skip: (req) => {
    const ip = req.ip || req.connection?.remoteAddress || "";
    return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1";
  },
}));

app.get("/health", (_, res) => res.json({ status: "ok" }));

// Unauthenticated probe that verifies Node -> Python connectivity end to end.
app.get("/api/health", (req, res) => proxyTo("/health", req, res));

app.use("/api/agents", apiKeyAuth, agentsRouter);
app.use("/api/events", apiKeyAuth, eventsRouter);
app.use("/api/dashboard", apiKeyAuth, dashboardRouter);
app.use("/api/incidents", apiKeyAuth, incidentsRouter);
app.use("/api/policies", apiKeyAuth, policiesRouter);
app.use("/api/artifacts", apiKeyAuth, artifactsRouter);
app.use("/api/workflows", apiKeyAuth, workflowsRouter);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Kavach backend running on port ${PORT}`));
