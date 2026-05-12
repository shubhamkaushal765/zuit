/**
 * Fan-out fixture for JavaScript/TypeScript — positive case for CPLX001-fan-out.
 *
 * This file imports more than 20 distinct modules to trigger the fan-out rule.
 */

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import http from "http";
import https from "https";
import url from "url";
import util from "util";
import stream from "stream";
import events from "events";
import buffer from "buffer";
import process from "process";
import readline from "readline";
import zlib from "zlib";
import net from "net";
import dns from "dns";
import child_process from "child_process";
import timers from "timers";
import assert from "assert";
import querystring from "querystring";
import string_decoder from "string_decoder";

/** Placeholder — the many imports above trigger CPLX001. */
export function placeholder(): string {
  return "fan-out-example";
}
