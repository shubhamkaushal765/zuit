/**
 * Express application with a permissive CORS configuration.
 */

import express from "express";
import cors from "cors";

const app = express();

// SEC011: origin: "*" allows any origin
app.use(cors({ origin: "*" }));

export { app };
