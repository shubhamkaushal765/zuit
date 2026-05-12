/**
 * Positive fixture for SEC003-shell-injection.
 *
 * Both signals are present:
 *   1. Import of ``child_process`` (a shell-exec module).
 *   2. A string literal that matches the shell-prefix command pattern.
 */

import { exec } from "child_process";

/** Run an arbitrary shell command — injection risk. */
export function runUserCommand(userInput: string): void {
  // The string literal below matches the shell-prefix pattern: 'bash -c'.
  const cmd = "bash -c " + userInput;
  exec(cmd);
}
