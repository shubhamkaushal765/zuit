/**
 * Weak-crypto fixture for JavaScript/TypeScript — positive case for SEC004-weak-crypto.
 *
 * Demonstrates use of deprecated hash algorithms SHA-1 and MD5.
 */

import crypto from "crypto";

/** Hash algorithm names used — these string literals trigger SEC004. */
const SHA1_ALGO = "sha1";
const MD5_ALGO = "md5";

/** Hash data using SHA-1 (insecure). */
export function hashWithSha1(data: string): string {
  const hash = crypto.createHash(SHA1_ALGO);
  hash.update(data);
  return hash.digest("hex");
}

/** Hash data using MD5 (insecure). */
export function hashWithMd5(data: string): string {
  const hash = crypto.createHash(MD5_ALGO);
  hash.update(data);
  return hash.digest("hex");
}
