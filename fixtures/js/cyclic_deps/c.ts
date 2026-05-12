/** Module c — imports a, creating a three-way cycle: a → b → c → a. */

import { funcA } from './a';

/** Function in module c. */
export function funcC(): string {
  return "c";
}
