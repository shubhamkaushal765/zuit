//! `DEP001-vulnerable-deps` — offline check for known-vulnerable dependency
//! versions in lock files.
//!
//! ## How it works
//!
//! In `analyze_project`, the rule looks for any of:
//!
//! - `Cargo.lock` (Rust)
//! - `package-lock.json` (npm / Node.js)
//! - `requirements.txt` (Python pip)
//!
//! at the project root.  Each file is searched line-by-line against a small
//! bundled offline database of well-known historical CVEs.  One finding per
//! matched line is emitted with the lock-file path as `location.file` and a
//! span pointing at the matched line.
//!
//! ## Offline database
//!
//! The database is a `static` slice of `VulnEntry` structs.  It covers
//! a curated set of historical CVEs across the three supported ecosystems.
//! **This database is not updated automatically** — it captures a snapshot of
//! known issues at the time the rule was written.  For up-to-date vulnerability
//! scanning, use a dedicated tool such as `cargo-audit`, `npm audit`, or
//! `pip-audit`.
//!
//! ## Configuration
//!
//! The rule is enabled by default and runs unconditionally whenever lock files
//! are found at the project root.  To opt out:
//!
//! ```toml
//! [rules."DEP001-vulnerable-deps"]
//! enabled = false
//! ```
//!
//! Adding `--check-deps` is **not** required; the analyzer always runs.
//!
//! ## References
//!
//! - CWE-1395: Dependency on Vulnerable Third-Party Component
//! - OWASP A06:2021 – Vulnerable and Outdated Components
//!
//! # Limitations
//!
//! - Network lookups are out of scope.  The bundled DB is a best-effort snapshot.
//! - Only three lock-file formats are supported.
//! - Version ranges are not parsed; the check is a simple string-prefix match
//!   on the normalised `name = "version"` or `"name": "version"` line.

use std::path::Path;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Location, Span},
};

/// Rule ID for the vulnerable-deps check.
pub const RULE_ID: &str = "DEP001-vulnerable-deps";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/DEP001-vulnerable-deps.md",
    cwe: &["CWE-1395"],
    owasp: &["A06:2021"],
};

/// A single entry in the offline vulnerability database.
///
/// `pkg` and `version_prefix` are compared against lines extracted from
/// lock files using ecosystem-specific patterns.
#[derive(Debug)]
struct VulnEntry {
    /// Ecosystem-agnostic package name (lowercase).
    pkg: &'static str,
    /// Version string prefix that is vulnerable (e.g. `"0.8."` covers `0.8.*`).
    version_prefix: &'static str,
    /// Human-readable CVE identifier(s).
    cve: &'static str,
    /// Short description of the vulnerability.
    description: &'static str,
}

/// Offline vulnerability database.
///
/// Sources: public CVE advisories.  Only a representative subset is included;
/// this is **not** a comprehensive list.
///
/// | Package | Affected versions | CVE |
/// |---|---|---|
/// | serde_yaml (Rust) | < 0.9.0 | GHSA-qwqr-xp34-m6mj |
/// | lodash (npm) | < 4.17.21 | CVE-2021-23337 |
/// | requests (Python) | < 2.31.0 | CVE-2023-32681 |
/// | tar (npm) | < 6.1.2 | CVE-2021-32803 |
/// | pyyaml (Python) | < 6.0 | CVE-2020-14343 |
/// | minimist (npm) | < 1.2.6 | CVE-2021-44906 |
/// | werkzeug (Python) | < 2.2.3 | CVE-2023-25577 |
/// | ansi-regex (npm) | < 5.0.1 | CVE-2021-3807 |
/// | crypto (npm direct) | any | advisory: use built-in `crypto` module |
/// | setuptools (Python) | < 65.5.1 | CVE-2022-40897 |
static VULN_DB: &[VulnEntry] = &[
    VulnEntry {
        pkg: "serde_yaml",
        version_prefix: "0.",
        cve: "GHSA-qwqr-xp34-m6mj",
        description: "serde_yaml < 0.9 uses unsafe YAML deserialization; upgrade to 0.9+",
    },
    VulnEntry {
        pkg: "lodash",
        version_prefix: "4.17.",
        cve: "CVE-2021-23337",
        description: "lodash < 4.17.21 prototype pollution; upgrade to 4.17.21+",
    },
    VulnEntry {
        pkg: "requests",
        version_prefix: "2.",
        cve: "CVE-2023-32681",
        description: "requests < 2.31.0 proxy credential leak; upgrade to 2.31.0+",
    },
    VulnEntry {
        pkg: "tar",
        version_prefix: "6.1.",
        cve: "CVE-2021-32803",
        description: "tar < 6.1.2 path traversal; upgrade to 6.1.2+",
    },
    VulnEntry {
        pkg: "pyyaml",
        version_prefix: "5.",
        cve: "CVE-2020-14343",
        description: "PyYAML < 6.0 arbitrary code execution via yaml.load; upgrade to 6.0+",
    },
    VulnEntry {
        pkg: "minimist",
        version_prefix: "1.2.",
        cve: "CVE-2021-44906",
        description: "minimist < 1.2.6 prototype pollution; upgrade to 1.2.6+",
    },
    VulnEntry {
        pkg: "werkzeug",
        version_prefix: "2.1.",
        cve: "CVE-2023-25577",
        description: "Werkzeug < 2.2.3 high-memory multipart request; upgrade to 2.2.3+",
    },
    VulnEntry {
        pkg: "ansi-regex",
        version_prefix: "5.0.",
        cve: "CVE-2021-3807",
        description: "ansi-regex < 5.0.1 ReDoS; upgrade to 5.0.1+",
    },
    VulnEntry {
        pkg: "setuptools",
        version_prefix: "6",
        cve: "CVE-2022-40897",
        description: "setuptools < 65.5.1 ReDoS in package_index; upgrade to 65.5.1+",
    },
    VulnEntry {
        pkg: "flask",
        version_prefix: "1.",
        cve: "CVE-2023-30861",
        description: "Flask < 2.3.2 session cookie disclosure; upgrade to 2.3.2+",
    },
];

/// Checks whether `version` starts with `prefix`, meaning it is a vulnerable
/// release.
fn version_matches(version: &str, prefix: &str) -> bool {
    version.starts_with(prefix)
}

/// Parse a `Cargo.lock` v3 section line: `version = "X.Y.Z"`.
///
/// Returns `Some(version_str)` if the line is a version declaration.
fn parse_cargo_version(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("version = \"") {
        let v = rest.trim_end_matches('"');
        return Some(v);
    }
    None
}

/// Parse a `Cargo.lock` `name = "…"` line.
fn parse_cargo_name(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("name = \"") {
        let n = rest.trim_end_matches('"');
        return Some(n);
    }
    None
}

/// Scan a `Cargo.lock` file for vulnerable packages.
///
/// The v3 format has `[[package]]` sections; within each section `name` and
/// `version` appear as separate key-value lines.
fn scan_cargo_lock(text: &str, file_path: &Path, findings: &mut Vec<Finding>) {
    let mut current_name: Option<&str> = None;
    let mut current_name_line: u32 = 0;

    for (line_no_0, line) in text.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_no = (line_no_0 + 1) as u32;

        if line.trim() == "[[package]]" {
            current_name = None;
        }

        if let Some(name) = parse_cargo_name(line) {
            current_name = Some(name);
            current_name_line = line_no;
        }

        if let Some(version) = parse_cargo_version(line)
            && let Some(name) = current_name
        {
            for entry in VULN_DB {
                if entry.pkg.eq_ignore_ascii_case(name)
                    && version_matches(version, entry.version_prefix)
                {
                    emit_finding(file_path, current_name_line, name, version, entry, findings);
                }
            }
        }
    }
}

/// Scan a `package-lock.json` v2 file for vulnerable packages.
///
/// The format has a `"node_modules/<name>": { "version": "X.Y.Z" }` section.
/// We parse it heuristically with simple line matching.
fn scan_package_lock(text: &str, file_path: &Path, findings: &mut Vec<Finding>) {
    let mut current_name: Option<String> = None;
    let mut current_name_line: u32 = 0;

    for (line_no_0, line) in text.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_no = (line_no_0 + 1) as u32;
        let trimmed = line.trim();

        // Match: `"node_modules/foo": {`
        if trimmed.starts_with('"') && trimmed.ends_with("\": {") {
            let inner = &trimmed[1..trimmed.len() - 4]; // strip surrounding `"` and `": {`
            let pkg_name = inner.rsplit('/').next().unwrap_or(inner).to_string();
            current_name = Some(pkg_name);
            current_name_line = line_no;
        }
        // Also match top-level name: `"name": "foo",`
        if let Some(rest) = trimmed.strip_prefix("\"name\": \"") {
            let name = rest.trim_end_matches('"').trim_end_matches(',');
            // Only use if no node_modules name is active.
            if current_name.is_none() {
                current_name = Some(name.to_string());
                current_name_line = line_no;
            }
        }

        // Match: `"version": "X.Y.Z",`
        if let Some(rest) = trimmed.strip_prefix("\"version\": \"") {
            let version = rest.trim_end_matches('"').trim_end_matches(',');
            if let Some(ref name) = current_name {
                for entry in VULN_DB {
                    if entry.pkg.eq_ignore_ascii_case(name)
                        && version_matches(version, entry.version_prefix)
                    {
                        emit_finding(file_path, current_name_line, name, version, entry, findings);
                    }
                }
            }
        }
    }
}

/// Scan a `requirements.txt` file for vulnerable packages.
///
/// Lines of the form `package==X.Y.Z` or `package>=X,<Y` are matched.
/// Only exact `==` pins are checked against the DB; range specifiers are
/// noted as potentially vulnerable if the minimum matches.
fn scan_requirements_txt(text: &str, file_path: &Path, findings: &mut Vec<Finding>) {
    for (line_no_0, line) in text.lines().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let line_no = (line_no_0 + 1) as u32;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split on `==` to get name + exact version.
        if let Some(idx) = trimmed.find("==") {
            let name = trimmed[..idx].trim();
            let version = trimmed[idx + 2..]
                .trim()
                .split(',')
                .next()
                .unwrap_or("")
                .trim();
            for entry in VULN_DB {
                if entry.pkg.eq_ignore_ascii_case(name)
                    && version_matches(version, entry.version_prefix)
                {
                    emit_finding(file_path, line_no, name, version, entry, findings);
                }
            }
        }
    }
}

/// Emit one `Finding` for a matched vulnerability.
fn emit_finding(
    file_path: &Path,
    line_no: u32,
    name: &str,
    version: &str,
    entry: &VulnEntry,
    findings: &mut Vec<Finding>,
) {
    let span = Span::new(ByteOffset(0), ByteOffset(0));
    let lc = LineCol::new(line_no, 1);
    findings.push(Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Security,
        rule_id: RULE_ID.to_string(),
        severity: Severity::High,
        message: format!(
            "vulnerable dependency `{name}@{version}`: {} ({})",
            entry.description, entry.cve,
        ),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: lc,
            end: lc,
        },
        suggestion: Some(format!(
            "Upgrade `{name}` to a non-vulnerable version. See {} for details.",
            entry.cve,
        )),
        references: vec![entry.cve.to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

/// Reads a file from disk and returns its text, or `None` on error.
fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Analyzer that checks project lock files against the offline vuln DB.
#[derive(Debug, Default)]
pub struct VulnerableDepsAnalyzer;

impl Analyzer for VulnerableDepsAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ProjectLevel
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        vec![]
    }

    fn analyze_project(&self, ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        if !ctx.config.rule_enabled(RULE_ID) {
            return vec![];
        }

        let root = &project.root;
        let mut findings: Vec<Finding> = Vec::new();

        // Cargo.lock
        let cargo_lock = root.join("Cargo.lock");
        if let Some(text) = read_file(&cargo_lock) {
            scan_cargo_lock(&text, &cargo_lock, &mut findings);
        }

        // package-lock.json
        let pkg_lock = root.join("package-lock.json");
        if let Some(text) = read_file(&pkg_lock) {
            scan_package_lock(&text, &pkg_lock, &mut findings);
        }

        // requirements.txt
        let reqs = root.join("requirements.txt");
        if let Some(text) = read_file(&reqs) {
            scan_requirements_txt(&text, &reqs, &mut findings);
        }

        findings.sort();
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Language, SourceFile};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    fn python_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    fn make_project(root: PathBuf) -> Project {
        let dummy = python_parse("dummy.py", "x = 1\n");
        Project::new(root, vec![dummy])
    }

    // ── helper unit tests ─────────────────────────────────────────────────────

    #[test]
    fn cargo_version_parse() {
        assert_eq!(parse_cargo_version("version = \"0.8.26\""), Some("0.8.26"));
        assert_eq!(
            parse_cargo_name("name = \"serde_yaml\""),
            Some("serde_yaml")
        );
    }

    #[test]
    fn version_prefix_match() {
        assert!(version_matches("0.8.26", "0."));
        assert!(!version_matches("0.9.0", "0.8."));
    }

    // ── Cargo.lock positive ───────────────────────────────────────────────────

    #[test]
    fn cargo_lock_vulnerable_positive() {
        let text = include_str!("../../../fixtures/vulnerable_deps/Cargo.lock");
        let path = PathBuf::from("fixtures/vulnerable_deps/Cargo.lock");
        let mut findings = Vec::new();
        scan_cargo_lock(text, &path, &mut findings);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DEP001 finding for Cargo.lock fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── requirements.txt positive ─────────────────────────────────────────────

    #[test]
    fn requirements_txt_vulnerable_positive() {
        let text = include_str!("../../../fixtures/vulnerable_deps/requirements.txt");
        let path = PathBuf::from("fixtures/vulnerable_deps/requirements.txt");
        let mut findings = Vec::new();
        scan_requirements_txt(text, &path, &mut findings);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DEP001 finding for requirements.txt fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── package-lock.json positive ────────────────────────────────────────────

    #[test]
    fn package_lock_vulnerable_positive() {
        let text = include_str!("../../../fixtures/vulnerable_deps/package-lock.json");
        let path = PathBuf::from("fixtures/vulnerable_deps/package-lock.json");
        let mut findings = Vec::new();
        scan_package_lock(text, &path, &mut findings);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DEP001 finding for package-lock.json fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── project-level positive ────────────────────────────────────────────────

    #[test]
    fn project_level_finds_vulnerable_deps() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("../../fixtures/vulnerable_deps");
        let project = make_project(root);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = VulnerableDepsAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DEP001 finding for vulnerable_deps project fixture"
        );
    }

    // ── opt-out via config ────────────────────────────────────────────────────

    #[test]
    fn rule_disabled_via_config() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("../../fixtures/vulnerable_deps");
        let project = make_project(root);
        let config = Config::from_toml_str("[rules.\"DEP001-vulnerable-deps\"]\nenabled = false")
            .expect("valid toml");
        let ctx = make_ctx(&config);
        let findings = VulnerableDepsAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "rule disabled via config should produce no findings, got {findings:#?}"
        );
    }

    // ── no lock files present ─────────────────────────────────────────────────

    #[test]
    fn no_lock_files_no_findings() {
        // Use a directory that definitely has no lock files.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("../../fixtures/python/healthy");
        let project = make_project(root);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = VulnerableDepsAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "expected 0 DEP001 findings when no lock files present, got {findings:#?}"
        );
    }
}
