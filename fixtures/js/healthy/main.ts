/**
 * A small, well-structured TypeScript module with no security issues.
 */

import { readFile } from "fs/promises";

/** Return a friendly greeting for the given name. */
export function greet(name: string): string {
  return `Hello, ${name}!`;
}

/** Return the sum of an array of integers. */
export function computeSum(numbers: number[]): number {
  let total = 0;
  for (const n of numbers) {
    total += n;
  }
  return total;
}

/** Asynchronously fetch data from a URL (stub). */
export async function fetchData(url: string): Promise<string | null> {
  if (!url) {
    return null;
  }
  return url;
}

/** Private helper — not part of the public API. */
function _internalHelper(value: number): boolean {
  return value > 0;
}

/** Process data items with basic validation. */
export class DataProcessor {
  private threshold: number;

  /** Initialise with a numeric threshold. */
  constructor(threshold: number) {
    this.threshold = threshold;
  }

  /** Return items that exceed the threshold. */
  process(items: number[]): number[] {
    return items.filter((x) => x > this.threshold);
  }
}
