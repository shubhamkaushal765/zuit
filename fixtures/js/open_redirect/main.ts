/**
 * Express endpoint with an open redirect vulnerability.
 */

import express from "express";

const app = express();

app.get("/go", (req, res) => {
  // SEC009: redirect target taken directly from query string
  res.redirect(req.query.url as string);
});

export { app };
