/**
 * Express endpoint with a Server-Side Request Forgery vulnerability.
 */

import express from "express";

const app = express();

app.get("/proxy", async (req, res) => {
  // SEC010: user-controlled URL flows directly into fetch
  const result = await fetch(`${req.query.url}/data`);
  const body = await result.text();
  res.send(body);
});

export { app };
