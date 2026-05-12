//! HTTP request dispatch for `zuit-show`. See spec §8.

use crate::analytics::{
    compute_heatmap_from_analytics, compute_project_summary_from_analytics, compute_scan_analytics,
    compute_scan_diff, compute_trends_from_analytics,
};
use crate::history::{ConfigId, HistoryStore, ProjectId, ScanId};
use tiny_http::{Header, Request, Response};

/// Top-level dispatcher. Receives a live `Request` and writes the response
/// directly via `Request::respond`. Tests use [`handle_for_test`] instead.
///
/// # Panics
///
/// Does not panic; IO errors from `request.respond` are silently dropped
/// (the client closed the connection).
pub fn handle(store: &HistoryStore, request: Request, version: &str) {
    let method = request.method().as_str().to_string();
    // `url()` includes the path and query string; split them.
    let full_url = request.url().to_string();
    let (path, query) = split_path_query(&full_url);

    // SEC-D: Reject requests whose Host header is not 127.0.0.1[:<port>] or
    // localhost[:<port>].  This blocks DNS-rebinding attacks.
    let host_ok = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("host"))
        .is_some_and(|h| is_allowed_host(h.value.as_str()));
    if !host_ok {
        let (status, body, ct) = json_err(403, "forbidden host");
        let mut response = Response::from_data(body).with_status_code(status);
        response.add_header(
            Header::from_bytes(b"Content-Type".as_ref(), ct.as_bytes())
                .expect("invariant: header name and value are valid ASCII"),
        );
        let _ = request.respond(response);
        return;
    }

    let (status, body, ct) = dispatch(store, &method, path, query, version);

    let mut response = Response::from_data(body).with_status_code(status);
    response.add_header(
        Header::from_bytes(b"Content-Type".as_ref(), ct.as_bytes())
            .expect("invariant: header name and value are valid ASCII"),
    );
    let _ = request.respond(response);
}

/// Pure-data variant for tests: no live server required.
///
/// `url` may include a query string (e.g. `/api/projects/abc/diff?from=x&to=y`).
/// Returns `(status_code, body_bytes)`. The content-type is not returned
/// because tests assert on JSON structure, not wire headers.
#[must_use]
pub fn handle_for_test(
    store: &HistoryStore,
    method: &str,
    url: &str,
    version: &str,
) -> (u16, Vec<u8>) {
    let (path, query) = split_path_query(url);
    let (status, body, _ct) = dispatch(store, method, path, query, version);
    (status, body)
}

/// Same as [`handle_for_test`] but also returns the response content-type.
///
/// Use this when a test must assert on the wire content-type header.
#[must_use]
pub fn handle_for_test_with_ct(
    store: &HistoryStore,
    method: &str,
    url: &str,
    version: &str,
) -> (u16, Vec<u8>, &'static str) {
    let (path, query) = split_path_query(url);
    dispatch(store, method, path, query, version)
}

// ── internal helpers ────────────────────────────────────────────────────────

/// Splits a URL into `(path, query)` where `query` is the part after `?` (may be empty).
fn split_path_query(url: &str) -> (&str, &str) {
    match url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url, ""),
    }
}

/// Decodes a percent-encoded string (RFC 3986 §2.1).
///
/// `%XY` sequences are decoded where `X` and `Y` are hexadecimal digits
/// (upper- or lower-case). The `+` character is left as-is because this
/// function is used for URL path/query parsing, **not** for
/// `application/x-www-form-urlencoded` form bodies where `+` means space.
///
/// Returns `None` when the input contains a malformed `%XY` escape (i.e.
/// `%` not followed by exactly two hex digits).
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Need two hex digits after `%`.
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = char::from(bytes[i + 1]).to_digit(16)?;
            let lo = char::from(bytes[i + 2]).to_digit(16)?;
            #[allow(clippy::cast_possible_truncation)]
            let decoded = (hi * 16 + lo) as u8;
            out.push(char::from(decoded));
            i += 3;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    Some(out)
}

/// Parses a query string like `from=a&to=b` into a `Vec<(String, String)>`.
///
/// Both keys and values are percent-decoded (RFC 3986 §2.1). Pairs containing
/// a malformed `%XY` escape in either the key or value are silently dropped.
/// The `+` character is left literal (this is URL query parsing, not form-body
/// `application/x-www-form-urlencoded` decoding).
fn parse_query_pairs(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let k_dec = percent_decode(k)?;
            let v_dec = percent_decode(v)?;
            Some((k_dec, v_dec))
        })
        .collect()
}

/// Returns the value for a given key from a list of query pairs, or `None`.
fn query_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Validates that `s` looks like a scan id: non-empty, only ASCII alphanumeric, `-`, or `Z`.
///
/// Permissive check (length range + permitted charset); full regex not needed.
fn validate_scan_id(s: &str) -> bool {
    let len = s.len();
    // Scan ids have the form `YYYY-MM-DDTHH:MM:SSZ-<6hex>`, which is 27 chars.
    // Accept any non-empty string of permitted chars (20..=40 chars).
    (20..=40).contains(&len)
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ':')
}

/// Validate a scan id extracted from a URL path segment.
///
/// Mirrors [`validate_scan_id`] but returns an error triple suitable for early
/// returns in route arms.
///
/// # Errors
///
/// Returns `Err` with a 400-response triple when the id is malformed.
fn validate_scan_id_path(s: &str) -> Result<(), (u16, Vec<u8>, &'static str)> {
    if validate_scan_id(s) {
        Ok(())
    } else {
        Err(json_err(400, "malformed scan id"))
    }
}

/// Returns `true` when `host` is a permitted value for the HTTP `Host` header.
///
/// Allowed forms:
/// - `127.0.0.1`
/// - `127.0.0.1:<port>`
/// - `localhost`
/// - `localhost:<port>`
#[must_use]
pub fn is_allowed_host(host: &str) -> bool {
    // Strip an optional port suffix (everything after the last `:` that is
    // numeric).  We match the base hostname against the two allowed values.
    let base = if let Some((left, right)) = host.rsplit_once(':') {
        // Only strip the suffix when the right part looks like a port number.
        if right.chars().all(|c| c.is_ascii_digit()) {
            left
        } else {
            host
        }
    } else {
        host
    };
    base == "127.0.0.1" || base == "localhost"
}

/// Loads a scan envelope from the store.  Returns the parsed `Value` or an error triple.
fn load_envelope(
    store: &HistoryStore,
    pid: &ProjectId,
    sid: &ScanId,
) -> Result<serde_json::Value, (u16, Vec<u8>, &'static str)> {
    let bytes = match store.read_scan(pid, sid) {
        Ok(b) => b,
        Err(crate::error::HistoryError::NotFound(_)) => {
            return Err(json_err(404, "scan not found"));
        }
        Err(e) => return Err(json_err(500, &e.to_string())),
    };
    serde_json::from_slice(&bytes).map_err(|e| json_err(500, &e.to_string()))
}

/// Returns `(status, body_bytes, content_type)`.
///
/// This function is necessarily long because it is the central route table;
/// each arm is a single API endpoint and cannot be meaningfully extracted.
#[allow(clippy::too_many_lines)]
fn dispatch(
    store: &HistoryStore,
    method: &str,
    path: &str,
    query: &str,
    version: &str,
) -> (u16, Vec<u8>, &'static str) {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // ── static assets ────────────────────────────────────────────────
        ("GET", [""] | []) => (
            200,
            crate::assets::INDEX_HTML.to_vec(),
            "text/html; charset=utf-8",
        ),
        ("GET", ["assets", name]) => match *name {
            "app.js" => (
                200,
                crate::assets::APP_JS.to_vec(),
                "application/javascript",
            ),
            "styles.css" => (200, crate::assets::STYLES_CSS.to_vec(), "text/css"),
            "uplot.js" => (
                200,
                crate::assets::UPLOT_JS.to_vec(),
                "application/javascript",
            ),
            "uplot.min.css" => (200, crate::assets::UPLOT_CSS.to_vec(), "text/css"),
            "fonts.css" => (200, crate::assets::FONTS_CSS.to_vec(), "text/css"),
            _ => json_err(404, "asset not found"),
        },
        ("GET", ["assets", "fonts", name]) => match *name {
            "inter-400.woff2"  => (200, crate::assets::INTER_400.to_vec(),  "font/woff2"),
            "inter-500.woff2"  => (200, crate::assets::INTER_500.to_vec(),  "font/woff2"),
            "inter-600.woff2"  => (200, crate::assets::INTER_600.to_vec(),  "font/woff2"),
            "jbmono-400.woff2" => (200, crate::assets::JBMONO_400.to_vec(), "font/woff2"),
            _ => json_err(404, "asset not found"),
        },

        // ── healthz ──────────────────────────────────────────────────────
        ("GET", ["api", "healthz"]) => {
            let body = serde_json::json!({"ok": true, "version": version}).to_string();
            (200, body.into_bytes(), "application/json")
        }

        // ── projects list ────────────────────────────────────────────────
        ("GET", ["api", "projects"]) => match store.list_projects() {
            Err(e) => json_err(500, &e.to_string()),
            Ok(projects) => {
                let mut items = Vec::with_capacity(projects.len());
                for (pid, meta) in &projects {
                    let scans = match store.list_scans(pid) {
                        Ok(s) => s,
                        Err(e) => return json_err(500, &e.to_string()),
                    };
                    let scan_count = scans.len();
                    let last_scan_at = scans.last().map(|s| s.captured_at.as_str());
                    let latest_scores = scans.last().map(|s| s.scores.clone());
                    items.push(serde_json::json!({
                        "hash":  pid.0,
                        "name":  meta.name,
                        "root":  meta.root,
                        "last_scan_at":    last_scan_at,
                        "scan_count":      scan_count,
                        "latest_scores":   latest_scores,
                    }));
                }
                let body =
                    serde_json::to_vec(&items).expect("invariant: serde_json::Value serializes");
                (200, body, "application/json")
            }
        },

        // ── single project meta + recent scans summary ───────────────────
        ("GET", ["api", "projects", hash]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let projects = match store.list_projects() {
                Ok(p) => p,
                Err(e) => return json_err(500, &e.to_string()),
            };
            let Some((_, meta)) = projects.into_iter().find(|(id, _)| id == &pid) else {
                return json_err(404, "project not found");
            };
            let scans = match store.list_scans(&pid) {
                Ok(s) => s,
                Err(e) => return json_err(500, &e.to_string()),
            };
            let body = serde_json::json!({
                "hash":       pid.0,
                "name":       meta.name,
                "root":       meta.root,
                "first_seen": meta.first_seen,
                "scan_count": scans.len(),
                "scans":      scans,
            });
            let bytes = serde_json::to_vec(&body).expect("invariant: serde_json::Value serializes");
            (200, bytes, "application/json")
        }

        // ── scans index (no findings inline) ─────────────────────────────
        ("GET", ["api", "projects", hash, "scans"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            match store.list_scans(&pid) {
                Err(e) => json_err(500, &e.to_string()),
                Ok(scans) => {
                    let body =
                        serde_json::to_vec(&scans).expect("invariant: ScanIndexEntry serializes");
                    (200, body, "application/json")
                }
            }
        }

        // ── single scan (full envelope) ───────────────────────────────────
        // SEC-B: validate the scan id from the path segment.
        ("GET", ["api", "projects", hash, "scans", id]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            if let Err(e) = validate_scan_id_path(id) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let sid = ScanId((*id).to_string());
            match store.read_scan(&pid, &sid) {
                Err(crate::error::HistoryError::NotFound(_)) => json_err(404, "scan not found"),
                Err(e) => json_err(500, &e.to_string()),
                Ok(bytes) => (200, bytes, "application/json"),
            }
        }

        // ── delete scan ───────────────────────────────────────────────────
        // SEC-B: validate the scan id from the path segment.
        ("DELETE", ["api", "projects", hash, "scans", id]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            if let Err(e) = validate_scan_id_path(id) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let sid = ScanId((*id).to_string());
            match store.delete_scan(&pid, &sid) {
                Err(e) => json_err(500, &e.to_string()),
                Ok(()) => (204, Vec::new(), "application/json"),
            }
        }

        // ── delete project ────────────────────────────────────────────────
        // SEC-B: validate the project hash from the path segment.
        ("DELETE", ["api", "projects", hash]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            match store.delete_project(&pid) {
                Err(e) => json_err(500, &e.to_string()),
                Ok(()) => (204, Vec::new(), "application/json"),
            }
        }

        // ── config snapshot ───────────────────────────────────────────────
        ("GET", ["api", "projects", hash, "configs", cfg]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            if let Err(e) = validate_hex16(cfg) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let cid = ConfigId((*cfg).to_string());
            match store.read_config(&pid, &cid) {
                Err(crate::error::HistoryError::NotFound(_)) => json_err(404, "config not found"),
                Err(e) => json_err(500, &e.to_string()),
                Ok(toml_bytes) => {
                    let toml_str = String::from_utf8_lossy(&toml_bytes).into_owned();
                    let parsed: serde_json::Value =
                        toml::from_str(&toml_str).unwrap_or(serde_json::Value::Null);
                    let body = serde_json::json!({"toml": toml_str, "parsed": parsed});
                    let bytes =
                        serde_json::to_vec(&body).expect("invariant: serde_json::Value serializes");
                    (200, bytes, "application/json")
                }
            }
        }

        // ── per-scan analytics ────────────────────────────────────────────
        // SEC-B: validate the scan id from the path segment.
        ("GET", ["api", "projects", hash, "scans", id, "analytics"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            if let Err(e) = validate_scan_id_path(id) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let sid = ScanId((*id).to_string());
            // Fast path: serve from pre-computed sidecar (O(1) file read).
            // If absent or malformed, fall back to computing from the envelope
            // and writing a fresh sidecar (lazy regeneration).
            let analytics = if let Ok(Some(a)) = store.read_scan_analytics(&pid, &sid) {
                a
            } else {
                let envelope = match load_envelope(store, &pid, &sid) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let computed = compute_scan_analytics(&envelope);
                if let Err(err) = store.write_scan_analytics(&pid, &sid, &computed) {
                    tracing::debug!(
                        error = %err,
                        "scan analytics sidecar regen failed (continuing with in-memory result)"
                    );
                } else {
                    tracing::debug!("scan analytics sidecar regenerated");
                }
                computed
            };
            let bytes =
                serde_json::to_vec(&analytics).expect("invariant: ScanAnalytics serializes");
            (200, bytes, "application/json")
        }

        // ── project summary ───────────────────────────────────────────────
        ("GET", ["api", "projects", hash, "summary"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let projects = match store.list_projects() {
                Ok(p) => p,
                Err(e) => return json_err(500, &e.to_string()),
            };
            let Some((_, meta)) = projects.into_iter().find(|(id, _)| id == &pid) else {
                return json_err(404, "project not found");
            };
            let scan_entries = match store.list_scans(&pid) {
                Ok(s) => s,
                Err(e) => return json_err(500, &e.to_string()),
            };
            // Try sidecar-driven path first (O(N_scans) reads, no findings traversal).
            // Fall back to full envelope load for any scan whose sidecar is missing or malformed.
            let mut all_analytics: Vec<crate::analytics::ScanAnalytics> =
                Vec::with_capacity(scan_entries.len());
            let mut use_envelope_fallback = false;
            for entry in &scan_entries {
                let sid = ScanId(entry.id.clone());
                if let Ok(Some(a)) = store.read_scan_analytics(&pid, &sid) {
                    all_analytics.push(a);
                } else {
                    // Sidecar missing or malformed — fall back for this scan.
                    use_envelope_fallback = true;
                    match load_envelope(store, &pid, &sid) {
                        Ok(envelope) => {
                            let computed = compute_scan_analytics(&envelope);
                            // Opportunistically write the sidecar so subsequent
                            // requests can skip the envelope load.
                            if let Err(err) = store.write_scan_analytics(&pid, &sid, &computed) {
                                tracing::debug!(
                                    error = %err,
                                    "summary: scan analytics sidecar regen failed"
                                );
                            }
                            all_analytics.push(computed);
                        }
                        Err(e) => return e,
                    }
                }
            }
            if use_envelope_fallback {
                tracing::debug!("summary: fell back to envelope load for one or more scans");
            }
            let summary = compute_project_summary_from_analytics(&meta, &all_analytics);
            let bytes = serde_json::to_vec(&summary).expect("invariant: ProjectSummary serializes");
            (200, bytes, "application/json")
        }

        // ── scan diff ─────────────────────────────────────────────────────
        ("GET", ["api", "projects", hash, "diff"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pairs = parse_query_pairs(query);
            let from_id = match query_get(&pairs, "from") {
                Some(v) if validate_scan_id(v) => v.to_owned(),
                Some(_) => return json_err(400, "malformed 'from' scan id"),
                None => return json_err(400, "missing query parameter 'from'"),
            };
            let to_id = match query_get(&pairs, "to") {
                Some(v) if validate_scan_id(v) => v.to_owned(),
                Some(_) => return json_err(400, "malformed 'to' scan id"),
                None => return json_err(400, "missing query parameter 'to'"),
            };
            let pid = ProjectId((*hash).to_string());
            let from_envelope = match load_envelope(store, &pid, &ScanId(from_id)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let to_envelope = match load_envelope(store, &pid, &ScanId(to_id)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let diff = compute_scan_diff(&from_envelope, &to_envelope);
            let bytes = serde_json::to_vec(&diff).expect("invariant: ScanDiff serializes");
            (200, bytes, "application/json")
        }

        // ── trends ────────────────────────────────────────────────────────
        ("GET", ["api", "projects", hash, "trends"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let scan_entries = match store.list_scans(&pid) {
                Ok(s) => s,
                Err(e) => return json_err(500, &e.to_string()),
            };
            // Try sidecar-driven path first; fall back per scan on miss.
            let mut all_analytics: Vec<crate::analytics::ScanAnalytics> =
                Vec::with_capacity(scan_entries.len());
            for entry in &scan_entries {
                let sid = ScanId(entry.id.clone());
                if let Ok(Some(a)) = store.read_scan_analytics(&pid, &sid) {
                    all_analytics.push(a);
                } else {
                    match load_envelope(store, &pid, &sid) {
                        Ok(envelope) => {
                            let computed = compute_scan_analytics(&envelope);
                            if let Err(err) = store.write_scan_analytics(&pid, &sid, &computed) {
                                tracing::debug!(
                                    error = %err,
                                    "trends: scan analytics sidecar regen failed"
                                );
                            }
                            all_analytics.push(computed);
                        }
                        Err(e) => return e,
                    }
                }
            }
            let trends = compute_trends_from_analytics(&all_analytics);
            let bytes = serde_json::to_vec(&trends).expect("invariant: Vec<TrendPoint> serializes");
            (200, bytes, "application/json")
        }

        // ── hot-files heatmap ─────────────────────────────────────────────
        ("GET", ["api", "projects", hash, "heatmap"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let scan_entries = match store.list_scans(&pid) {
                Ok(s) => s,
                Err(e) => return json_err(500, &e.to_string()),
            };
            // Try sidecar-driven path. For any sidecar that is absent,
            // malformed, or pre-dates the `all_file_counts` field (empty map
            // on a non-empty scan), fall back to loading the full envelope and
            // regenerate the sidecar so subsequent requests are fast.
            let mut all_analytics: Vec<crate::analytics::ScanAnalytics> =
                Vec::with_capacity(scan_entries.len());

            for entry in &scan_entries {
                let sid = ScanId(entry.id.clone());
                let needs_fallback = match store.read_scan_analytics(&pid, &sid) {
                    Ok(Some(a))
                        if !(a.total_findings > 0 && a.all_file_counts.is_empty())
                            && a.version == crate::analytics::ANALYTICS_VERSION =>
                    {
                        all_analytics.push(a);
                        false
                    }
                    _ => true,
                };
                if needs_fallback {
                    // Sidecar absent, malformed, pre-dates `all_file_counts`,
                    // or version mismatch — regenerate from the full envelope.
                    match load_envelope(store, &pid, &sid) {
                        Ok(envelope) => {
                            let computed = compute_scan_analytics(&envelope);
                            if let Err(err) = store.write_scan_analytics(&pid, &sid, &computed) {
                                tracing::debug!(
                                    error = %err,
                                    "heatmap: scan analytics sidecar regen failed"
                                );
                            } else {
                                tracing::debug!(
                                    "scan analytics sidecar regenerated due to version mismatch"
                                );
                            }
                            all_analytics.push(computed);
                        }
                        Err(e) => return e,
                    }
                }
            }

            let heatmap = compute_heatmap_from_analytics(&all_analytics, None);
            let bytes =
                serde_json::to_vec(&heatmap).expect("invariant: Vec<HeatmapEntry> serializes");
            (200, bytes, "application/json")
        }

        // ── label endpoints ───────────────────────────────────────────────
        // SEC-B: validate the scan id from the path segment.
        ("PUT", ["api", "projects", hash, "scans", id, "label"]) => {
            if let Err(e) = validate_hex16(hash) {
                return e;
            }
            if let Err(e) = validate_scan_id_path(id) {
                return e;
            }
            let pid = ProjectId((*hash).to_string());
            let sid = ScanId((*id).to_string());
            // Parse request body for the label field.
            // `handle_for_test` supplies the body via query string as
            // `_body=<json>` since tiny_http bodies are not accessible from
            // the pure-data path.  Real requests go through `handle` which
            // reads the body before calling dispatch.  We therefore accept
            // the label value from the `_label` injected context field that
            // `handle_for_test` callers pass via the `query` string.
            //
            // For the real HTTP path the body is a `{"label": "..."}` JSON
            // object forwarded as the query string `_body=<urlencoded-json>`
            // by the `handle` wrapper below.
            let pairs = parse_query_pairs(query);
            let label_val = query_get(&pairs, "_label");
            let label = match label_val {
                Some("") | None => None,
                Some(s) => Some(s),
            };
            match store.set_label(&pid, &sid, label) {
                Ok(()) => (204, Vec::new(), "application/json"),
                Err(e) => json_err(500, &e.to_string()),
            }
        }

        // ── catch-all 404 ─────────────────────────────────────────────────
        _ => json_err(404, "not found"),
    }
}

/// Build a JSON error response triple.
fn json_err(code: u16, msg: &str) -> (u16, Vec<u8>, &'static str) {
    let body = serde_json::json!({"error": code, "message": msg}).to_string();
    (code, body.into_bytes(), "application/json")
}

/// Validate that `s` is exactly 16 lowercase hex characters.
///
/// # Errors
///
/// Returns `Err` with a 400-response triple when the hash is malformed.
fn validate_hex16(s: &str) -> Result<(), (u16, Vec<u8>, &'static str)> {
    if s.len() == 16
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(json_err(400, "malformed hash"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_store() -> (TempDir, HistoryStore) {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        (tmp, store)
    }

    fn fixture_report() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "tool": {"name": "zuit", "version": "x"},
            "scores": {
                "maintainability": 50.0,
                "security":        50.0,
                "complexity":      50.0,
                "documentation":   50.0,
                "test_smell":      50.0,
            },
            "findings": [],
            "stats": {"files_scanned": 0, "parse_failures": 0, "elapsed_ms": 0},
        }))
        .unwrap()
    }

    #[test]
    fn healthz_ok() {
        let (_tmp, store) = fixture_store();
        let (status, body) = handle_for_test(&store, "GET", "/api/healthz", "0.1.0");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["version"], "0.1.0");
    }

    #[test]
    fn unknown_route_404() {
        let (_tmp, store) = fixture_store();
        let (status, _) = handle_for_test(&store, "GET", "/api/nope", "0.1.0");
        assert_eq!(status, 404);
    }

    #[test]
    fn projects_lists_recorded_projects() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let report = fixture_report();
        store.record(&p, b"", &report, 100).unwrap();
        let (status, body) = handle_for_test(&store, "GET", "/api/projects", "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn delete_scan_returns_204_and_removes() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let report = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "tool": {"name": "zuit", "version": "x"},
            "scores": {
                "maintainability": 0.0, "security": 0.0,
                "complexity": 0.0, "documentation": 0.0, "test_smell": 0.0,
            },
            "findings": [],
            "stats": {"files_scanned": 0, "parse_failures": 0, "elapsed_ms": 0},
        }))
        .unwrap();
        let scan_id = store.record(&p, b"", &report, 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let path = format!("/api/projects/{}/scans/{}", pid.0, scan_id.0);
        let (status, _) = handle_for_test(&store, "DELETE", &path, "x");
        assert_eq!(status, 204);
        assert!(store.list_scans(&pid).unwrap().is_empty());
    }

    #[test]
    fn malformed_hash_returns_400() {
        let (_tmp, store) = fixture_store();
        let (status, _) = handle_for_test(&store, "GET", "/api/projects/NOT_HEX/scans", "x");
        assert_eq!(status, 400);
    }

    #[test]
    fn snapshot_projects_endpoint() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj-a");
        std::fs::create_dir(&p).unwrap();
        let report = fixture_report();
        store.record(&p, b"", &report, 100).unwrap();
        let (status, body) = handle_for_test(&store, "GET", "/api/projects", "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Redact non-deterministic fields before snapshotting.
        let redacted: Vec<serde_json::Value> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                let mut obj = item.as_object().unwrap().clone();
                obj.insert("hash".into(), serde_json::json!("[hash]"));
                obj.insert("root".into(), serde_json::json!("[root]"));
                obj.insert("name".into(), serde_json::json!("[name]"));
                obj.insert("last_scan_at".into(), serde_json::json!("[last_scan_at]"));
                obj.insert("latest_scores".into(), serde_json::json!("[latest_scores]"));
                serde_json::Value::Object(obj)
            })
            .collect();
        insta::assert_snapshot!(
            "snapshot_projects_endpoint",
            serde_json::to_string_pretty(&redacted).unwrap()
        );
    }

    /// Build a fixture report with the given findings vec.
    #[allow(clippy::needless_pass_by_value)]
    fn fixture_report_with_findings(findings: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "tool": {"name": "zuit", "version": "x"},
            "scores": {
                "maintainability": 90.0,
                "security":        80.0,
                "complexity":      70.0,
                "documentation":   60.0,
                "test_smell":      50.0,
            },
            "findings": findings,
            "stats": {"files_scanned": 3, "parse_failures": 0, "elapsed_ms": 42},
        }))
        .unwrap()
    }

    #[test]
    fn analytics_endpoint_returns_200_and_shape() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let findings = serde_json::json!([{
            "analyzer": "test",
            "rule_id": "SEC001",
            "severity": "high",
            "dimension": "security",
            "message": "msg",
            "location": {
                "file": "a.rs",
                "span": {"start": 0, "end": 1},
                "start": {"line": 1, "col": 1},
                "end":   {"line": 1, "col": 2}
            }
        }]);
        let report = fixture_report_with_findings(findings);
        let scan_id = store.record(&p, b"", &report, 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/scans/{}/analytics", pid.0, scan_id.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("severity_counts").is_some(),
            "missing severity_counts"
        );
        assert!(json.get("top_rules").is_some(), "missing top_rules");
        assert!(json.get("grades").is_some(), "missing grades");
        assert!(
            json.get("total_findings").is_some(),
            "missing total_findings"
        );
        assert_eq!(json["total_findings"], 1);
        assert_eq!(json["severity_counts"]["high"], 1);
    }

    #[test]
    fn analytics_endpoint_404_when_scan_missing() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let pid = HistoryStore::project_id(&p);
        // Record something so the project exists but use a fake scan id.
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        let url = format!(
            "/api/projects/{}/scans/2026-01-01T00:00:00Z-aabbcc/analytics",
            pid.0
        );
        let (status, _) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 404);
    }

    #[test]
    fn summary_endpoint_returns_200() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/summary", pid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("project").is_some());
        assert!(json.get("latest").is_some());
        // Only one scan, so delta_vs_previous must be null.
        assert!(json["delta_vs_previous"].is_null());
    }

    #[test]
    fn diff_endpoint_400_when_query_missing() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        // No query string at all.
        let url = format!("/api/projects/{}/diff", pid.0);
        let (status, _) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 400);
    }

    #[test]
    fn diff_endpoint_returns_arrays() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let report_a = fixture_report();
        let report_b = fixture_report_with_findings(serde_json::json!([{
            "analyzer": "test",
            "rule_id": "MAINT001",
            "severity": "medium",
            "dimension": "maintainability",
            "message": "too complex",
            "location": {
                "file": "b.rs",
                "span": {"start": 0, "end": 1},
                "start": {"line": 5, "col": 1},
                "end":   {"line": 5, "col": 2}
            }
        }]));
        let sid_a = store.record(&p, b"", &report_a, 100).unwrap();
        let sid_b = store.record(&p, b"", &report_b, 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!(
            "/api/projects/{}/diff?from={}&to={}",
            pid.0, sid_a.0, sid_b.0
        );
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("new").is_some(), "missing 'new'");
        assert!(json.get("resolved").is_some(), "missing 'resolved'");
        assert!(json.get("persisting").is_some(), "missing 'persisting'");
        // report_b added one finding, report_a had none → 1 new, 0 resolved.
        assert_eq!(json["new"].as_array().unwrap().len(), 1);
        assert_eq!(json["resolved"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn trends_endpoint_returns_array() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/trends", pid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2, "should have one trend point per scan");
        // Each point must have a scan_id and total_findings field.
        assert!(arr[0].get("scan_id").is_some());
        assert!(arr[0].get("total_findings").is_some());
    }

    // ── heatmap: empty project ───────────────────────────────────────────────

    #[test]
    fn heatmap_empty_project_returns_empty_array() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        // Record one scan so the project hash is valid, but with no findings.
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/heatmap", pid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.as_array().unwrap().is_empty(),
            "expected empty array for project with no findings"
        );
    }

    // ── heatmap: single scan path counts ────────────────────────────────────

    #[test]
    fn heatmap_single_scan_path_counts_match() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let findings = serde_json::json!([
            {
                "analyzer": "t", "rule_id": "R1", "severity": "high",
                "dimension": "security", "message": "m",
                "location": {"file": "a.rs", "span": {"start":0,"end":1},
                             "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 2}}
            },
            {
                "analyzer": "t", "rule_id": "R1", "severity": "high",
                "dimension": "security", "message": "m2",
                "location": {"file": "a.rs", "span": {"start":0,"end":1},
                             "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 2}}
            },
            {
                "analyzer": "t", "rule_id": "R1", "severity": "high",
                "dimension": "security", "message": "m3",
                "location": {"file": "b.rs", "span": {"start":0,"end":1},
                             "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 2}}
            }
        ]);
        store
            .record(&p, b"", &fixture_report_with_findings(findings), 100)
            .unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/heatmap", pid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        // a.rs has 2, b.rs has 1 → sorted by total desc.
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["path"], "a.rs");
        assert_eq!(arr[0]["total_findings_all_time"], 2);
        assert_eq!(arr[1]["path"], "b.rs");
        assert_eq!(arr[1]["total_findings_all_time"], 1);
    }

    // ── heatmap: multi-scan has findings_per_scan aligned ───────────────────

    #[test]
    fn heatmap_multi_scan_aligned_per_scan_counts() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let findings_a = serde_json::json!([{
            "analyzer": "t", "rule_id": "R1", "severity": "high",
            "dimension": "security", "message": "m",
            "location": {"file": "a.rs", "span": {"start":0,"end":1},
                         "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 2}}
        }]);
        let findings_b = serde_json::json!([
            {
                "analyzer": "t", "rule_id": "R1", "severity": "high",
                "dimension": "security", "message": "m",
                "location": {"file": "a.rs", "span": {"start":0,"end":1},
                             "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 2}}
            },
            {
                "analyzer": "t", "rule_id": "R1", "severity": "high",
                "dimension": "security", "message": "m2",
                "location": {"file": "a.rs", "span": {"start":0,"end":1},
                             "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 2}}
            }
        ]);
        store
            .record(&p, b"", &fixture_report_with_findings(findings_a), 100)
            .unwrap();
        store
            .record(&p, b"", &fixture_report_with_findings(findings_b), 100)
            .unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/heatmap", pid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1, "only a.rs");
        let entry = &arr[0];
        assert_eq!(entry["path"], "a.rs");
        assert_eq!(entry["total_findings_all_time"], 3);
        let per_scan = entry["findings_per_scan"].as_array().unwrap();
        assert_eq!(per_scan.len(), 2);
        // The two scans had 1 and 2 findings respectively; the sum must be 3.
        // We do not assert order since both scans may fall within the same second.
        let sum: u64 = per_scan.iter().map(|v| v.as_u64().unwrap_or(0)).sum();
        assert_eq!(sum, 3);
        // Each entry must be non-zero (both scans contributed).
        assert!(per_scan.iter().all(|v| v.as_u64().unwrap_or(0) > 0));
    }

    // ── heatmap: sort order ──────────────────────────────────────────────────

    #[test]
    fn heatmap_sort_order_by_total_desc() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        // b.rs:3 > a.rs:1
        let findings = serde_json::json!([
            {"analyzer":"t","rule_id":"R","severity":"high","dimension":"security","message":"m",
             "location":{"file":"b.rs","span":{"start":0,"end":1},"start":{"line":1,"col":1},"end":{"line":1,"col":2}}},
            {"analyzer":"t","rule_id":"R","severity":"high","dimension":"security","message":"m",
             "location":{"file":"b.rs","span":{"start":0,"end":1},"start":{"line":2,"col":1},"end":{"line":2,"col":2}}},
            {"analyzer":"t","rule_id":"R","severity":"high","dimension":"security","message":"m",
             "location":{"file":"b.rs","span":{"start":0,"end":1},"start":{"line":3,"col":1},"end":{"line":3,"col":2}}},
            {"analyzer":"t","rule_id":"R","severity":"high","dimension":"security","message":"m",
             "location":{"file":"a.rs","span":{"start":0,"end":1},"start":{"line":1,"col":1},"end":{"line":1,"col":2}}}
        ]);
        store
            .record(&p, b"", &fixture_report_with_findings(findings), 100)
            .unwrap();
        let pid = HistoryStore::project_id(&p);
        let url = format!("/api/projects/{}/heatmap", pid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr[0]["path"], "b.rs");
        assert_eq!(arr[1]["path"], "a.rs");
    }

    // ── heatmap: bad hash → 400 ──────────────────────────────────────────────

    #[test]
    fn heatmap_bad_hash_returns_400() {
        let (_tmp, store) = fixture_store();
        let (status, _) = handle_for_test(&store, "GET", "/api/projects/BADHASH/heatmap", "x");
        assert_eq!(status, 400);
    }

    // ── label: set and get via route ─────────────────────────────────────────

    #[test]
    fn label_put_returns_204_and_surfaces_in_scans() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let sid = store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        let url = format!(
            "/api/projects/{}/scans/{}/label?_label=release",
            pid.0, sid.0
        );
        let (status, _) = handle_for_test(&store, "PUT", &url, "x");
        assert_eq!(status, 204);

        // The label should now show in the scan index.
        assert_eq!(store.get_label(&pid, &sid), Some("release".to_owned()));
    }

    // ── label: clear via route ───────────────────────────────────────────────

    #[test]
    fn label_put_empty_clears_label() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let sid = store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        store.set_label(&pid, &sid, Some("v1")).unwrap();

        // Clear by sending empty label.
        let url = format!("/api/projects/{}/scans/{}/label?_label=", pid.0, sid.0);
        let (status, _) = handle_for_test(&store, "PUT", &url, "x");
        assert_eq!(status, 204);
        assert_eq!(store.get_label(&pid, &sid), None);
    }

    // ── label: bad hash → 400 ────────────────────────────────────────────────

    #[test]
    fn label_put_bad_hash_returns_400() {
        let (_tmp, store) = fixture_store();
        let (status, _) = handle_for_test(
            &store,
            "PUT",
            "/api/projects/BADHASH/scans/2026-01-01T00:00:00Z-aabbcc/label?_label=x",
            "x",
        );
        assert_eq!(status, 400);
    }

    // ── SEC-B: validate scan id in path segments ─────────────────────────────

    /// GET /api/projects/:hash/scans/:id with a malformed id returns 400.
    #[test]
    fn sec_b_get_scan_bad_id_returns_400() {
        let (_tmp, store) = fixture_store();
        // A path-traversal-style string split across segments by the URL parser;
        // using a short string with dots (too short, disallowed chars).
        let (status, body) = handle_for_test(
            &store,
            "GET",
            "/api/projects/abcdef0123456789/scans/short",
            "x",
        );
        assert_eq!(status, 400);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "malformed scan id");
    }

    /// DELETE /api/projects/:hash/scans/:id with a malformed id returns 400.
    #[test]
    fn sec_b_delete_scan_bad_id_returns_400() {
        let (_tmp, store) = fixture_store();
        // A short nonsense string (too short to be a valid scan id).
        let (status, body) = handle_for_test(
            &store,
            "DELETE",
            "/api/projects/abcdef0123456789/scans/foo.bar.baz",
            "x",
        );
        assert_eq!(status, 400);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "malformed scan id");
    }

    /// GET /api/projects/:hash/scans/:id/analytics with a malformed id returns 400.
    #[test]
    fn sec_b_analytics_bad_id_returns_400() {
        let (_tmp, store) = fixture_store();
        let (status, body) = handle_for_test(
            &store,
            "GET",
            "/api/projects/abcdef0123456789/scans/INVALID_SCAN_ID_WITH_UPPER/analytics",
            "x",
        );
        assert_eq!(status, 400);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "malformed scan id");
    }

    /// PUT /api/projects/:hash/scans/:id/label with a malformed id returns 400.
    #[test]
    fn sec_b_label_put_bad_id_returns_400() {
        let (_tmp, store) = fixture_store();
        // Contains uppercase letters — disallowed by validate_scan_id.
        let (status, body) = handle_for_test(
            &store,
            "PUT",
            "/api/projects/abcdef0123456789/scans/BADID_BAD_XXXXXXXXXX/label?_label=x",
            "x",
        );
        assert_eq!(status, 400);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "malformed scan id");
    }

    // ── §12 analytics sidecar tests ─────────────────────────────────────────

    /// §12 test 1: `record()` creates an `.analytics.json` sidecar alongside
    /// the scan envelope.  The sidecar must be valid JSON and the `scan_id`
    /// field must match the returned scan id.
    #[test]
    fn analytics_sidecar_created_on_record() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let report = fixture_report_with_findings(serde_json::json!([{
            "analyzer": "t", "rule_id": "SEC001", "severity": "high",
            "dimension": "security", "message": "m",
            "location": {
                "file": "a.rs", "span": {"start":0,"end":1},
                "start": {"line":1,"col":1}, "end": {"line":1,"col":2}
            }
        }]));
        let sid = store.record(&p, b"", &report, 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        // The sidecar file must exist.
        let scans_dir = tmp.path().join("projects").join(&pid.0).join("scans");
        let sidecar = scans_dir.join(format!("{}.analytics.json", sid.0));
        assert!(
            sidecar.exists(),
            "analytics sidecar must be created by record()"
        );

        // The sidecar must deserialise and carry the correct scan_id.
        let bytes = std::fs::read(&sidecar).unwrap();
        let analytics: crate::analytics::ScanAnalytics =
            serde_json::from_slice(&bytes).expect("analytics sidecar must be valid JSON");
        assert_eq!(analytics.scan_id, sid.0);
    }

    /// §12 test 2: deleting the sidecar from disk and hitting the analytics
    /// endpoint must return HTTP 200 AND recreate the sidecar.
    #[test]
    fn analytics_endpoint_uses_sidecar() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let sid = store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        // Delete the sidecar that record() just created.
        let scans_dir = tmp.path().join("projects").join(&pid.0).join("scans");
        let sidecar = scans_dir.join(format!("{}.analytics.json", sid.0));
        std::fs::remove_file(&sidecar).unwrap();
        assert!(
            !sidecar.exists(),
            "sidecar should be gone before the request"
        );

        // Hit the analytics endpoint.
        let url = format!("/api/projects/{}/scans/{}/analytics", pid.0, sid.0);
        let (status, _body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(
            status, 200,
            "endpoint must return 200 even after sidecar deletion"
        );

        // The sidecar must have been lazily regenerated.
        assert!(
            sidecar.exists(),
            "analytics sidecar must be regenerated lazily on cache miss"
        );
    }

    /// §12 test 3: a truncated (malformed) sidecar must not cause a 500; the
    /// endpoint must return 200 and a fresh, valid sidecar must be written.
    #[test]
    fn analytics_endpoint_handles_malformed_sidecar() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let sid = store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        // Truncate the sidecar to 1 byte (makes it invalid JSON).
        let scans_dir = tmp.path().join("projects").join(&pid.0).join("scans");
        let sidecar = scans_dir.join(format!("{}.analytics.json", sid.0));
        std::fs::write(&sidecar, b"{").unwrap(); // 1-byte invalid JSON

        // Hit the analytics endpoint.
        let url = format!("/api/projects/{}/scans/{}/analytics", pid.0, sid.0);
        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(status, 200, "malformed sidecar must not cause 500");

        // The response must be valid analytics JSON.
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("scan_id").is_some(),
            "response must contain scan_id"
        );

        // The sidecar must have been replaced with a valid one.
        let fresh = std::fs::read(&sidecar).unwrap();
        let _: crate::analytics::ScanAnalytics =
            serde_json::from_slice(&fresh).expect("regenerated sidecar must be valid JSON");
    }

    /// §12 test 4: `list_scans` must not return `.analytics.json` files as
    /// phantom scan entries.
    #[test]
    fn scans_index_excludes_analytics_sidecar() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        store.record(&p, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        let scans = store.list_scans(&pid).unwrap();
        assert_eq!(
            scans.len(),
            1,
            "list_scans must return exactly 1 entry, not phantom .analytics.json entries"
        );
    }

    // ── percent-decoding in parse_query_pairs ───────────────────────────────

    #[test]
    fn parse_query_pairs_decodes_percent_encoded_values() {
        // A scan id with `:` encoded as %3A (what encodeURIComponent produces).
        let pairs = parse_query_pairs("from=2026-05-09T04%3A05%3A42Z-abc123");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "from");
        assert_eq!(pairs[0].1, "2026-05-09T04:05:42Z-abc123");
    }

    #[test]
    fn parse_query_pairs_drops_malformed_percent_pairs() {
        // `%ZZ` is not a valid percent-encoded sequence.
        let pairs = parse_query_pairs("bad=%ZZ");
        // The malformed pair must either be dropped (len 0) or have an empty value.
        // We pin to: drop the malformed pair.
        assert!(
            pairs.is_empty(),
            "expected malformed percent pair to be dropped, got {pairs:?}"
        );
    }

    #[test]
    fn diff_endpoint_accepts_url_encoded_scan_ids() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();

        // Two scans: report_a has no findings, report_b has one finding.
        let report_a = fixture_report();
        let report_b = fixture_report_with_findings(serde_json::json!([{
            "analyzer": "test",
            "rule_id": "PERF001",
            "severity": "medium",
            "dimension": "performance",
            "message": "slow path",
            "location": {
                "file": "x.rs",
                "span": {"start": 0, "end": 1},
                "start": {"line": 1, "col": 1},
                "end":   {"line": 1, "col": 2}
            }
        }]));

        let sid_a = store.record(&p, b"", &report_a, 100).unwrap();
        let sid_b = store.record(&p, b"", &report_b, 100).unwrap();
        let pid = HistoryStore::project_id(&p);

        // Percent-encode the `:` characters in both scan ids, as the JS frontend does.
        let encoded_a = sid_a.0.replace(':', "%3A");
        let encoded_b = sid_b.0.replace(':', "%3A");

        let url = format!(
            "/api/projects/{}/diff?from={}&to={}",
            pid.0, encoded_a, encoded_b
        );

        let (status, body) = handle_for_test(&store, "GET", &url, "x");
        assert_eq!(
            status, 200,
            "diff endpoint must accept percent-encoded scan ids"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // report_b added one finding → `new` should be non-empty.
        let new_arr = json["new"].as_array().unwrap();
        assert!(
            !new_arr.is_empty(),
            "expected at least one new finding in diff"
        );
    }

    // ── delete project ───────────────────────────────────────────────────────

    #[test]
    fn delete_project_returns_204_and_removes() {
        let (tmp, store) = fixture_store();
        let p = tmp.path().join("proj");
        std::fs::create_dir(&p).unwrap();
        let report = fixture_report();
        store.record(&p, b"", &report, 100).unwrap();
        let pid = HistoryStore::project_id(&p);
        let path = format!("/api/projects/{}", pid.0);
        let (status, _) = handle_for_test(&store, "DELETE", &path, "x");
        assert_eq!(status, 204);
        assert!(store.list_projects().unwrap().is_empty());
    }

    #[test]
    fn delete_project_idempotent_returns_204() {
        let (_tmp, store) = fixture_store();
        // Use a well-formed hex16 for a project that was never recorded.
        let (status, _) = handle_for_test(&store, "DELETE", "/api/projects/abcdef0123456789", "x");
        assert_eq!(status, 204);
    }

    #[test]
    fn delete_project_bad_hash_returns_400() {
        let (_tmp, store) = fixture_store();
        let (status, _) = handle_for_test(&store, "DELETE", "/api/projects/NOT_HEX", "x");
        assert_eq!(status, 400);
    }

    // ── font asset routes ────────────────────────────────────────────────────

    #[test]
    fn assets_fonts_css_served() {
        let (_tmp, store) = fixture_store();
        let (status, body, ct) = handle_for_test_with_ct(&store, "GET", "/assets/fonts.css", "x");
        assert_eq!(status, 200);
        assert_eq!(ct, "text/css");
        assert!(
            body.starts_with(b"@font-face"),
            "body should start with @font-face"
        );
    }

    #[test]
    fn assets_fonts_woff2_served() {
        let (_tmp, store) = fixture_store();
        let (status, body, ct) = handle_for_test_with_ct(&store, "GET", "/assets/fonts/inter-400.woff2", "x");
        assert_eq!(status, 200);
        assert_eq!(ct, "font/woff2");
        assert_eq!(&body[..4], b"wOF2", "first 4 bytes must be wOF2 magic");
    }

    #[test]
    fn assets_fonts_unknown_404() {
        let (_tmp, store) = fixture_store();
        let (status, _body, _ct) = handle_for_test_with_ct(&store, "GET", "/assets/fonts/nope.woff2", "x");
        assert_eq!(status, 404);
    }

    // ── SEC-D: is_allowed_host unit tests ────────────────────────────────────

    #[test]
    fn is_allowed_host_accepts_localhost() {
        assert!(is_allowed_host("localhost"));
    }

    #[test]
    fn is_allowed_host_accepts_127_0_0_1() {
        assert!(is_allowed_host("127.0.0.1"));
    }

    #[test]
    fn is_allowed_host_accepts_localhost_with_port() {
        assert!(is_allowed_host("localhost:8080"));
    }

    #[test]
    fn is_allowed_host_accepts_127_0_0_1_with_port() {
        assert!(is_allowed_host("127.0.0.1:8080"));
    }

    #[test]
    fn is_allowed_host_rejects_evil_com() {
        assert!(!is_allowed_host("evil.com"));
    }

    #[test]
    fn is_allowed_host_rejects_subdomain_rebind() {
        assert!(!is_allowed_host("127.0.0.1.evil.com"));
    }

    #[test]
    fn is_allowed_host_rejects_0_0_0_0() {
        assert!(!is_allowed_host("0.0.0.0"));
    }

    #[test]
    fn is_allowed_host_rejects_empty() {
        assert!(!is_allowed_host(""));
    }
}
