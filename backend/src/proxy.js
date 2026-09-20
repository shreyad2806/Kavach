// Forwards a request to the unified Python backend and relays the response.
//
// Hardening over the previous version:
//   - forwards x-api-key upstream (required by the artifact/scanner routes;
//     the key is never logged)
//   - preserves the query string
//   - enforces an upstream timeout (no indefinite hangs) -> 504
//   - distinguishes connection failure (502) from a real upstream response
//   - tolerates non-JSON / empty upstream bodies without misreporting as 502
//   - consistent JSON error shape: { error, detail?, status? }

export const DEFAULT_TIMEOUT_MS = 15_000;
export const WORKFLOW_START_TIMEOUT_MS = 120_000;

function upstreamTimeoutMs(overrideMs) {
  if (overrideMs) return overrideMs;
  const configured = Number(process.env.UPSTREAM_TIMEOUT_MS);
  return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_TIMEOUT_MS;
}

function buildQuery(query = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) params.append(key, item);
    } else {
      params.append(key, value);
    }
  }
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

export async function proxyTo(path, req, res, { timeoutMs: overrideMs } = {}) {
  const base = process.env.PYTHON_API_URL;
  if (!base) {
    return res
      .status(500)
      .json({ error: "Backend misconfigured", detail: "PYTHON_API_URL is not set" });
  }

  const url = `${base}${path}${buildQuery(req.query)}`;
  const timeoutMs = upstreamTimeoutMs(overrideMs);

  const headers = {};
  // Forward the API key so upstream routes that require it can authorize.
  const apiKey = req.headers["x-api-key"];
  if (apiKey) headers["x-api-key"] = apiKey;

  const init = {
    method: req.method,
    headers,
    signal: AbortSignal.timeout(timeoutMs),
  };

  if (!["GET", "HEAD"].includes(req.method)) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(req.body ?? {});
  }

  let upstream;
  try {
    upstream = await fetch(url, init);
  } catch (err) {
    if (err && (err.name === "TimeoutError" || err.name === "AbortError")) {
      return res.status(504).json({
        error: "Upstream timeout",
        detail: `Python API did not respond within ${timeoutMs}ms`,
      });
    }
    return res
      .status(502)
      .json({ error: "Python API unreachable", detail: err?.message ?? String(err) });
  }

  let text;
  try {
    text = await upstream.text();
  } catch (err) {
    return res
      .status(502)
      .json({ error: "Failed to read upstream response", detail: err?.message ?? String(err) });
  }

  if (!text) {
    return res.status(upstream.status).send("");
  }

  try {
    return res.status(upstream.status).json(JSON.parse(text));
  } catch {
    // Upstream answered but not with JSON (e.g. an HTML error page).
    return res.status(upstream.status >= 400 ? upstream.status : 502).json({
      error: "Upstream returned a non-JSON response",
      status: upstream.status,
    });
  }
}
