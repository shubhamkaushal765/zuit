/** Module b — imports c, creating a three-way cycle: a → b → c → a. */

import { funcC } from './c';

/** Function in module b. */
export function funcB(): string {
  return "b";
}
