/**
 * Positive fixture for SEC005-insecure-deser: uses node-serialize unsafely.
 */

import serialize from "node-serialize";

/** Deserialize user-supplied data (insecure). */
export function loadUserData(data: string): unknown {
  return serialize.unserialize(data);
}
