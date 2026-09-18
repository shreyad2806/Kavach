// Forwards a request to the Python FastAPI and pipes the response back.
export async function proxyTo(path, req, res) {
  const base = process.env.PYTHON_API_URL;
  const url = `${base}${path}`;
  try {
    const upstream = await fetch(url, {
      method: req.method,
      headers: { "Content-Type": "application/json" },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : JSON.stringify(req.body),
    });
    const data = await upstream.json();
    res.status(upstream.status).json(data);
  } catch (err) {
    res.status(502).json({ error: "Python API unreachable", detail: err.message });
  }
}
