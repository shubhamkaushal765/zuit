/**
 * Positive fixture for SEC007-path-traversal: reads files with user input containing `..`.
 */

import * as fs from "fs";
import * as http from "http";

/** Serve a file based on user-supplied path (path traversal risk). */
export function serveFile(req: http.IncomingMessage, basePath: string): Buffer {
  const userPath = (req as any).query?.name ?? "";
  return fs.readFileSync(basePath + "/.." + userPath);
}
