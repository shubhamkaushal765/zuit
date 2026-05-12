/**
 * Analyse all source files under `path` and return a JSON string.
 *
 * The JSON object matches the `zuit_core::Report` schema.
 *
 * @param path - Absolute or relative path to a directory or file to analyse.
 * @returns A JSON string containing findings, scores, and statistics.
 */
export declare function analyze(path: string): string;

/**
 * Return the zuit package version string.
 *
 * @returns SemVer version string (e.g. `"0.1.0"`).
 */
export declare function version(): string;
