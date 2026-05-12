/** Module a — imports b, creating a three-way cycle: a → b → c → a. */

import { funcB } from './b';

/** Function in module a. */
export function funcA(): string {
  return "a";
}
