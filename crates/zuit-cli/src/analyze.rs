//! Implementation of the `zuit analyze` subcommand.
//!
//! Entry point: [`run`].  Returns the desired process exit code (0 or 1).

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use zuit_core::cache::{CacheStore as _, JsonCacheStore};
use zuit_core::{Config, Engine, Severity};
use zuit_report::{RenderOptions, ReportFormat, render};

use crate::cli::{AnalyzeArgs, FailOnLevel, Format};
use crate::registry_builtin::build_registry;

/// Resolves the [`Config`] for an analysis run.
///
/// Resolution order:
/// 1. If `--config <path>` is given, load from that path (error if missing).
/// 2. Otherwise search for `zuit.toml` starting at `root` and walking
///    upward through parent directories until the filesystem root.
/// 3. If no file is found, return `Config::default()`.
fn resolve_config(config_flag: Option<&Path>, root: &Path) -> Result<Config> {
    if let Some(explicit) = config_flag {
        return Config::load(explicit)
            .with_context(|| format!("loading config from {}", explicit.display()));
    }

    // Walk upward from root looking for zuit.toml.
    let mut dir = root.to_path_buf();
    loop {
        let candidate = dir.join("zuit.toml");
        if candidate.exists() {
            return Config::load(&candidate)
                .with_context(|| format!("loading config from {}", candidate.display()));
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }

    Ok(Config::default())
}

/// Converts the CLI `--format` flag into a [`ReportFormat`].
fn to_report_format(fmt: Format) -> ReportFormat {
    match fmt {
        Format::Json => ReportFormat::Json,
        Format::Terminal => ReportFormat::Terminal,
        Format::Markdown => ReportFormat::Markdown,
        Format::Sarif => ReportFormat::Sarif,
        Format::Checkstyle => ReportFormat::Checkstyle,
        Format::Junit => ReportFormat::Junit,
    }
}

/// Maps a [`FailOnLevel`] to the corresponding [`Severity`] threshold.
///
/// The `--fail-on` threshold is *inclusive*: any finding with severity ≥
/// the threshold causes a non-zero exit.
fn threshold_severity(level: FailOnLevel) -> Severity {
    match level {
        FailOnLevel::Info => Severity::Info,
        FailOnLevel::Low => Severity::Low,
        FailOnLevel::Medium => Severity::Medium,
        FailOnLevel::High => Severity::High,
        FailOnLevel::Critical => Severity::Critical,
    }
}

/// Determines the process exit code based on `--fail-on` and the findings.
///
/// Returns 1 if any finding has severity ≥ `threshold`, 0 otherwise.
/// Returns 0 if `threshold` is `None` (the flag was not set).
fn compute_exit_code(findings: &[zuit_core::Finding], threshold: Option<Severity>) -> i32 {
    let Some(threshold) = threshold else {
        return 0;
    };
    i32::from(findings.iter().any(|f| f.severity >= threshold))
}

/// Loads a baseline JSON file and returns the set of suppressed (`file`, `rule_id`,
/// `span_start`) triples.
///
/// Baseline comparisons drop any finding that appears in the baseline — i.e.
/// whose `(file, rule_id, location.span.start)` triple matches a baseline entry.
fn load_baseline(path: &Path) -> Result<std::collections::HashSet<BaselineKey>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading baseline file {}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).with_context(|| "parsing baseline JSON")?;

    let mut keys = std::collections::HashSet::new();
    if let Some(findings) = json.get("findings").and_then(serde_json::Value::as_array) {
        for f in findings {
            let file = f
                .pointer("/location/file")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let rule_id = f
                .get("rule_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let span_start = f
                .pointer("/location/span/start")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            keys.insert(BaselineKey {
                file,
                rule_id,
                span_start,
            });
        }
    }
    Ok(keys)
}

/// Filters findings in-place to keep only those matching the given OWASP and
/// CWE allowlists. Both checks are case-insensitive; an empty allowlist
/// disables that check (does not reject everything). When both allowlists are
/// non-empty, a finding must satisfy **both** (set intersection).
///
/// Order of `findings` is preserved, so the engine's deterministic sort is
/// retained.
fn apply_taxonomy_filters(
    findings: &mut Vec<zuit_core::Finding>,
    owasp_allow: &[String],
    cwe_allow: &[String],
) {
    if owasp_allow.is_empty() && cwe_allow.is_empty() {
        return;
    }
    let owasp_norm: Vec<String> = owasp_allow.iter().map(|s| s.to_uppercase()).collect();
    let cwe_norm: Vec<String> = cwe_allow.iter().map(|s| s.to_uppercase()).collect();

    findings.retain(|f| {
        let owasp_ok = owasp_norm.is_empty()
            || f.owasp
                .iter()
                .any(|o| owasp_norm.iter().any(|w| o.eq_ignore_ascii_case(w)));
        let cwe_ok = cwe_norm.is_empty()
            || f.cwe
                .iter()
                .any(|c| cwe_norm.iter().any(|w| c.eq_ignore_ascii_case(w)));
        owasp_ok && cwe_ok
    });
}

/// The comparison key used when applying a baseline.
#[derive(Debug, PartialEq, Eq, Hash)]
struct BaselineKey {
    file: String,
    rule_id: String,
    span_start: u64,
}

impl BaselineKey {
    fn from_finding(f: &zuit_core::Finding) -> Self {
        Self {
            file: f.location.file.to_string_lossy().into_owned(),
            rule_id: f.rule_id.clone(),
            span_start: u64::from(f.location.span.start.0),
        }
    }
}

/// Runs the `analyze` subcommand and returns the desired process exit code.
///
/// # Errors
///
/// Returns an error if:
/// - `--config` points to an unreadable or invalid TOML file.
/// - The analysis path does not exist or cannot be walked.
/// - Report rendering fails (only SARIF is unimplemented in v1).
/// - `--output` cannot be created or written.
pub fn run(args: &AnalyzeArgs) -> Result<i32> {
    // 1. Resolve configuration.
    let config = resolve_config(args.config.as_deref(), &args.path)?;

    // 2. Build registry and engine.
    let registry = build_registry();
    let engine = Engine::new(registry);

    // 3. Run analysis (with or without incremental cache).
    let use_cache = config.history.cache && !args.no_cache;
    let mut report = if use_cache {
        // Locate cache dir relative to the project root (same dir as the
        // resolved config or the analysis path itself).
        let cache_dir =
            zuit_core::path::project_root(&args.path, args.config.as_deref()).join(".zuit-cache");
        let store = JsonCacheStore::new(cache_dir);
        let mut cache = store.load().unwrap_or_default();

        let r = engine
            .analyze_path_cached(&args.path, &config, &mut cache)
            .with_context(|| format!("analyzing path {}", args.path.display()))?;

        // Best-effort save; failure does not affect the exit code.
        if let Err(e) = store.save(&cache) {
            tracing::warn!("cache save failed: {e:#}");
        }
        r
    } else {
        engine
            .analyze_path(&args.path, &config)
            .with_context(|| format!("analyzing path {}", args.path.display()))?
    };

    // 4. Apply baseline if given.
    if let Some(ref baseline_path) = args.baseline {
        let baseline = load_baseline(baseline_path)?;
        report.findings.retain(|f| {
            let key = BaselineKey::from_finding(f);
            !baseline.contains(&key)
        });
    }

    // 4b. Apply --owasp / --cwe filters (rule-pack selection).
    //
    // Filters run after `--baseline` so that the baseline still suppresses on
    // the original key, and before exit-code/render so that `--fail-on` and
    // the rendered output reflect the filtered set.
    apply_taxonomy_filters(&mut report.findings, &args.owasp, &args.cwe);

    // 5. Determine exit code before we move `report`.
    let threshold = args.fail_on.map(threshold_severity);
    let exit_code = compute_exit_code(&report.findings, threshold);

    // 6. Render.
    let format = to_report_format(args.format);
    let opts = RenderOptions {
        use_color: !args.no_color,
        use_hyperlinks: args.hyperlinks,
    };
    let rendered = render(format, &report, &opts).with_context(|| "rendering report")?;

    // 7. Write output.
    match args.output {
        Some(ref out_path) => {
            let mut file = std::fs::File::create(out_path)
                .with_context(|| format!("creating output file {}", out_path.display()))?;
            file.write_all(rendered.as_bytes())
                .with_context(|| format!("writing to output file {}", out_path.display()))?;
        }
        None => {
            print!("{rendered}");
        }
    }

    // 8. Auto-save to history (best-effort; failures are only logged).
    if !args.no_save
        && config.history.auto_save
        && let Err(e) = save_to_history(&args.path, args.config.as_deref(), &config, &report)
    {
        tracing::warn!("history auto-save failed: {e:#}");
    }

    Ok(exit_code)
}

/// Persists the scan result to `~/.zuit/` for `zuit show`.
///
/// All errors are returned to the caller; the caller logs and continues.
fn save_to_history(
    args_path: &std::path::Path,
    config_flag: Option<&std::path::Path>,
    config: &zuit_core::Config,
    report: &zuit_core::Report,
) -> anyhow::Result<()> {
    let home = std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".zuit"))
        .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    let store = zuit_show::HistoryStore::open(home);
    let project_root = zuit_core::path::project_root(args_path, config_flag);
    let report_json = zuit_report::render(
        zuit_report::ReportFormat::Json,
        report,
        &zuit_report::RenderOptions::default(),
    )?;
    let toml = if let Some(p) = config_flag {
        std::fs::read(p).unwrap_or_default()
    } else {
        let candidate = project_root.join("zuit.toml");
        std::fs::read(&candidate).unwrap_or_default()
    };
    store.record(
        &project_root,
        &toml,
        report_json.as_bytes(),
        config.history.max_scans_per_project,
    )?;
    Ok(())
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use zuit_core::{
        AnalyzerId, Dimension, Finding, Severity,
        span::{ByteOffset, LineCol, Location, Span},
    };

    fn make_finding(rule: &str, sev: Severity, start: u32) -> Finding {
        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Security,
            rule_id: rule.to_string(),
            severity: sev,
            message: "test".to_string(),
            location: Location {
                file: PathBuf::from("file.rs"),
                span: Span::new(ByteOffset(start), ByteOffset(start + 1)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }

    fn finding_with_taxonomy(rule: &str, cwe: Vec<&str>, owasp: Vec<&str>) -> Finding {
        let mut f = make_finding(rule, Severity::Medium, 0);
        f.cwe = cwe.into_iter().map(String::from).collect();
        f.owasp = owasp.into_iter().map(String::from).collect();
        f
    }

    // ── apply_taxonomy_filters ─────────────────────────────────────────────

    #[test]
    fn taxonomy_filter_noop_when_no_filters() {
        let mut fs = vec![
            finding_with_taxonomy("R1", vec!["CWE-89"], vec!["A03:2021"]),
            finding_with_taxonomy("R2", vec![], vec![]),
        ];
        apply_taxonomy_filters(&mut fs, &[], &[]);
        assert_eq!(fs.len(), 2, "no filters → no change");
    }

    #[test]
    fn taxonomy_filter_keeps_only_owasp_matches() {
        let mut fs = vec![
            finding_with_taxonomy("R1", vec!["CWE-89"], vec!["A03:2021"]),
            finding_with_taxonomy("R2", vec!["CWE-22"], vec!["A01:2021"]),
        ];
        apply_taxonomy_filters(&mut fs, &["A03:2021".to_string()], &[]);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].rule_id, "R1");
    }

    #[test]
    fn taxonomy_filter_owasp_is_case_insensitive() {
        let mut fs = vec![finding_with_taxonomy("R1", vec![], vec!["A03:2021"])];
        apply_taxonomy_filters(&mut fs, &["a03:2021".to_string()], &[]);
        assert_eq!(fs.len(), 1, "lowercase user input should still match");
    }

    #[test]
    fn taxonomy_filter_keeps_only_cwe_matches() {
        let mut fs = vec![
            finding_with_taxonomy("R1", vec!["CWE-89"], vec![]),
            finding_with_taxonomy("R2", vec!["CWE-22"], vec![]),
        ];
        apply_taxonomy_filters(&mut fs, &[], &["CWE-22".to_string()]);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].rule_id, "R2");
    }

    #[test]
    fn taxonomy_filter_intersects_owasp_and_cwe() {
        let mut fs = vec![
            // matches OWASP only
            finding_with_taxonomy("R1", vec!["CWE-89"], vec!["A03:2021"]),
            // matches both → kept
            finding_with_taxonomy("R2", vec!["CWE-22"], vec!["A03:2021"]),
            // matches CWE only
            finding_with_taxonomy("R3", vec!["CWE-22"], vec!["A01:2021"]),
        ];
        apply_taxonomy_filters(&mut fs, &["A03:2021".to_string()], &["CWE-22".to_string()]);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].rule_id, "R2");
    }

    #[test]
    fn taxonomy_filter_drops_findings_with_no_taxonomy() {
        let mut fs = vec![finding_with_taxonomy("R1", vec![], vec![])];
        apply_taxonomy_filters(&mut fs, &["A03:2021".to_string()], &[]);
        assert!(fs.is_empty(), "no owasp tags → cannot match an allowlist");
    }

    #[test]
    fn taxonomy_filter_preserves_input_order() {
        let mut fs = vec![
            finding_with_taxonomy("Z", vec!["CWE-22"], vec![]),
            finding_with_taxonomy("A", vec!["CWE-22"], vec![]),
            finding_with_taxonomy("M", vec!["CWE-22"], vec![]),
        ];
        apply_taxonomy_filters(&mut fs, &[], &["CWE-22".to_string()]);
        let order: Vec<&str> = fs.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(order, vec!["Z", "A", "M"], "filter must not re-sort");
    }

    // ── compute_exit_code ──────────────────────────────────────────────────

    #[test]
    fn no_fail_on_always_exits_zero() {
        let findings = vec![make_finding("X", Severity::Critical, 0)];
        assert_eq!(compute_exit_code(&findings, None), 0);
    }

    #[test]
    fn fail_on_high_exits_one_when_high_present() {
        let findings = vec![make_finding("X", Severity::High, 0)];
        assert_eq!(compute_exit_code(&findings, Some(Severity::High)), 1);
    }

    #[test]
    fn fail_on_high_exits_one_when_critical_present() {
        let findings = vec![make_finding("X", Severity::Critical, 0)];
        assert_eq!(compute_exit_code(&findings, Some(Severity::High)), 1);
    }

    #[test]
    fn fail_on_high_exits_zero_when_only_medium() {
        let findings = vec![make_finding("X", Severity::Medium, 0)];
        assert_eq!(compute_exit_code(&findings, Some(Severity::High)), 0);
    }

    #[test]
    fn fail_on_critical_exits_zero_for_high() {
        let findings = vec![make_finding("X", Severity::High, 0)];
        assert_eq!(compute_exit_code(&findings, Some(Severity::Critical)), 0);
    }

    #[test]
    fn fail_on_info_exits_one_for_any_finding() {
        let findings = vec![make_finding("X", Severity::Info, 0)];
        assert_eq!(compute_exit_code(&findings, Some(Severity::Info)), 1);
    }

    #[test]
    fn empty_findings_always_exits_zero() {
        assert_eq!(compute_exit_code(&[], Some(Severity::Info)), 0);
    }

    // ── baseline diff ──────────────────────────────────────────────────────

    #[test]
    fn baseline_key_from_finding() {
        let f = make_finding("SEC001", Severity::High, 42);
        let key = BaselineKey::from_finding(&f);
        assert_eq!(key.rule_id, "SEC001");
        assert_eq!(key.span_start, 42);
    }

    #[test]
    fn resolve_config_default_when_no_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = resolve_config(None, tmp.path()).unwrap();
        // Default config has empty exclusions.
        assert!(cfg.general.exclude.is_empty());
    }

    #[test]
    fn resolve_config_loads_from_explicit_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg_path = tmp.path().join("test.toml");
        std::fs::write(&cfg_path, "[general]\nfollow_symlinks = true\n").unwrap();
        let cfg = resolve_config(Some(&cfg_path), tmp.path()).unwrap();
        assert!(cfg.general.follow_symlinks);
    }

    #[test]
    fn resolve_config_finds_toml_in_parent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            tmp.path().join("zuit.toml"),
            "[general]\nfollow_symlinks = true\n",
        )
        .unwrap();
        let cfg = resolve_config(None, &sub).unwrap();
        assert!(cfg.general.follow_symlinks);
    }
}
