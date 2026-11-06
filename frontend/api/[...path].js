/**
 * Same-origin Vercel BFF.
 *
 * Browser requests /api/*; this function attaches the server-only API key and
 * forwards to the existing AWS Node BFF. No credential is exposed in VITE_*.
 * Keep long-running workflow/scanner execution on AWS (Lambda/Fargate/Step
 * Functions); this function is a thin authenticated transport boundary.
 */
export const config = { maxDuration: 60 };

const ALLOWED_METHODS = new Set(["GET", "POST", "PATCH", "DELETE"]);

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (!ALLOWED_METHODS.has(req.method || "GET")) {
    res.setHeader("Allow", "GET, POST, PATCH, DELETE");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const requestHost = req.headers.host;
  const origin = req.headers.origin;
  if (origin && requestHost) {
    try {
      const originUrl = new URL(origin);
      if (originUrl.host !== requestHost) {
        return res.status(403).json({ error: "Cross-origin request rejected" });
      }
    } catch {
      return res.status(403).json({ error: "Invalid request origin" });
    }
  }

  const upstreamBase = process.env.KAVACH_AWS_BFF_URL;
  const apiKey = process.env.KAVACH_API_KEY;
  if (!upstreamBase || !apiKey) {
    return res.status(503).json({
      error: "Vercel BFF is not configured",
      detail: "Set KAVACH_AWS_BFF_URL and KAVACH_API_KEY in server-side environment variables.",
    });
  }

  const incoming = new URL(req.url || "/", "https://vercel.invalid");
  const apiPath = incoming.pathname.replace(/^\/api(?=\/|$)/, "") || "/";
  const upstreamUrl = new URL("/api" + apiPath, upstreamBase);
  upstreamUrl.search = incoming.search;

  const headers = { "x-api-key": apiKey, "accept": "application/json" };
  if (req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];

  const init = {
    method: req.method || "GET",
    headers,
    signal: AbortSignal.timeout(55_000),
  };
  if (!["GET", "HEAD"].includes(init.method)) {
    init.body = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {});
    headers["content-type"] = "application/json";
  }

  try {
    const upstream = await fetch(upstreamUrl, init);
    const contentType = upstream.headers.get("content-type");
    if (contentType) res.setHeader("Content-Type", contentType);
    const body = await upstream.arrayBuffer();
    return res.status(upstream.status).send(Buffer.from(body));
  } catch (error) {
    const timedOut = error?.name === "TimeoutError" || error?.name === "AbortError";
    return res.status(timedOut ? 504 : 502).json({
      error: timedOut ? "Upstream timeout" : "AWS backend unavailable",
      detail: timedOut ? "The AWS API did not respond within 55 seconds." : "The request could not reach the AWS API.",
    });
  }
}
