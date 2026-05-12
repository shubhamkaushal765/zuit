//! [`Analyzer`] trait, [`Dimension`], [`Severity`], [`SupportedLanguages`],
//! [`RuleMeta`], [`AnalysisContext`], and [`Project`].
//!
//! Analyzers consume a [`crate::parsed::ParsedFile`] (or an entire [`Project`])
//! and return a list of [`crate::finding::Finding`]s.  Cross-language analyzers
//! only look at the [`crate::index::SemanticIndex`]; language-specific ones may
//! additionally call [`crate::parsed::ParsedFile::native`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::config::Config;
use crate::finding::Finding;
use crate::id::{AnalyzerId, LanguageId};
use crate::parsed::ParsedFile;

/// The quality dimension addressed by an analyzer.
///
/// The closed variants cover the five v1 dimensions.  `Custom` provides an
/// escape hatch for downstream consumers that need to introduce a new dimension
/// without forking the crate.
///
/// # Serialization
///
/// The five v1 variants serialise as lowercase strings (`"maintainability"`,
/// `"security"`, etc.).  `Custom(s)` serialises as the raw string `s`.
/// Deserialization is symmetric: any string not matching a built-in name is
/// deserialized into `Custom(s.to_string())` — unknown strings round-trip
/// correctly rather than erroring with `unknown_variant`.
///
/// # Ordering
///
/// The derived `Ord` follows variant declaration order:
/// `Maintainability < Security < Complexity < Documentation < TestSmell < Custom(_)`.
/// Within `Custom` variants, ordering is lexicographic on the inner string.
/// This order is intentional and stable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension {
    /// Code that is hard to read, modify, or extend.
    Maintainability,
    /// Code patterns that introduce vulnerabilities.
    Security,
    /// Structural properties that correlate with defect rates (cyclomatic,
    /// cognitive complexity, fan-out, cycles).
    Complexity,
    /// Missing or inadequate documentation of the public API.
    Documentation,
    /// Test code quality: low assertion density, skipped tests, bad ratios.
    TestSmell,
    /// A user-defined dimension not covered by the v1 built-ins.
    Custom(String),
}

impl serde::Serialize for Dimension {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Self::Maintainability => "maintainability",
            Self::Security => "security",
            Self::Complexity => "complexity",
            Self::Documentation => "documentation",
            Self::TestSmell => "test_smell",
            Self::Custom(name) => name.as_str(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for Dimension {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        match s.as_ref() {
            "maintainability" => Ok(Self::Maintainability),
            "security" => Ok(Self::Security),
            "complexity" => Ok(Self::Complexity),
            "documentation" => Ok(Self::Documentation),
            "test_smell" => Ok(Self::TestSmell),
            // Unknown strings round-trip into Custom rather than erroring.
            other => Ok(Self::Custom(other.to_string())),
        }
    }
}

impl std::fmt::Display for Dimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Maintainability => f.write_str("maintainability"),
            Self::Security => f.write_str("security"),
            Self::Complexity => f.write_str("complexity"),
            Self::Documentation => f.write_str("documentation"),
            Self::TestSmell => f.write_str("test_smell"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}

/// The severity of a [`crate::finding::Finding`].
///
/// The ordering from lowest to highest is `Info < Low < Medium < High < Critical`.
/// This ordering is used both for `--fail-on` threshold comparisons and for the
/// scoring formula in [`crate::score`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational: worth knowing but not necessarily actionable.
    Info,
    /// Low: minor issue unlikely to cause problems on its own.
    Low,
    /// Medium: moderate issue that should be addressed before release.
    Medium,
    /// High: serious issue that is likely to cause bugs or vulnerabilities.
    High,
    /// Critical: must be fixed immediately; high confidence of harm.
    Critical,
}

/// Specifies which languages an [`Analyzer`] supports.
///
/// `All` means the analyzer works on any language whose frontend populates a
/// [`crate::index::SemanticIndex`].  `Only` carries a small inline list of
/// [`LanguageId`]s to keep the common case (one or two languages) allocation-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedLanguages {
    /// The analyzer applies to all registered languages.
    All,
    /// The analyzer applies only to the listed languages.
    Only(SmallVec<[LanguageId; 4]>),
}

impl SupportedLanguages {
    /// Returns `true` if `lang` is covered by this constraint.
    #[must_use]
    pub fn supports(&self, lang: LanguageId) -> bool {
        match self {
            Self::All => true,
            Self::Only(ids) => ids.contains(&lang),
        }
    }
}

/// Static metadata about a single rule emitted by an [`Analyzer`].
///
/// The `doc_path` points to a markdown file in `docs/rules/` that explains the
/// rule, its rationale, and remediation guidance.
///
/// `cwe` and `owasp` carry the rule's mapping into industry-standard
/// taxonomies. They are used directly when emitting findings (so SARIF and
/// JSON consumers do not need a separate lookup table) and when listing rules
/// via `zuit list analyzers`. Both default to an empty slice for rules
/// that have no canonical mapping (e.g. some maintainability heuristics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    /// Stable rule identifier (e.g. `"MAINT001-cyclomatic"`).
    pub id: &'static str,
    /// Default severity used when the config does not override it.
    pub default_severity: Severity,
    /// Relative path to the rule's documentation file.
    pub doc_path: &'static str,
    /// CWE entries this rule maps to (e.g. `&["CWE-798"]`). Empty if none.
    pub cwe: &'static [&'static str],
    /// OWASP categories this rule maps to (e.g. `&["A07:2021"]`). Empty if none.
    pub owasp: &'static [&'static str],
}

impl RuleMeta {
    /// Returns a freshly-allocated `Vec<String>` of this rule's CWE entries.
    #[must_use]
    pub fn cwe_vec(&self) -> Vec<String> {
        self.cwe.iter().map(|s| (*s).to_string()).collect()
    }

    /// Returns a freshly-allocated `Vec<String>` of this rule's OWASP entries.
    #[must_use]
    pub fn owasp_vec(&self) -> Vec<String> {
        self.owasp.iter().map(|s| (*s).to_string()).collect()
    }
}

/// Context passed to every [`Analyzer::analyze_file`] call.
///
/// Provides access to the project-level configuration so that analyzers can
/// read rule-specific thresholds (e.g. the cyclomatic complexity threshold).
#[derive(Debug)]
pub struct AnalysisContext<'a> {
    /// Project configuration (parsed from `zuit.toml` or defaults).
    pub config: &'a Config,
}

impl<'a> AnalysisContext<'a> {
    /// Creates a new `AnalysisContext` with the given configuration.
    #[must_use]
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }
}

/// A complete project as seen by [`Analyzer::analyze_project`].
///
/// Holds all successfully-parsed files so that project-wide analyzers (e.g.
/// cycle detection) can reason about the full dependency graph.
#[derive(Debug)]
pub struct Project {
    /// Root directory of the project.
    pub root: PathBuf,
    /// All successfully-parsed files in lexicographic path order.
    pub files: Vec<ParsedFile>,
}

impl Project {
    /// Creates a `Project` from its root path and parsed file list.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, files: Vec<ParsedFile>) -> Self {
        Self {
            root: root.into(),
            files,
        }
    }
}

/// How the engine should dispatch this analyzer.
///
/// - `FileLevel` — the engine calls `analyze_file` for every file whose
///   language is supported. The default; appropriate for cross-language and
///   language-specific analyzers that examine each file independently.
/// - `ProjectLevel` — `analyze_file` is never called by the engine; the
///   analyzer's logic lives entirely in `analyze_project`. Use this for rules
///   that need the cross-file [`Project`] view (cycle detection, duplicate code,
///   vulnerable deps, test-ratio).
/// - `ExternalTool` — same as `ProjectLevel` from the engine's perspective,
///   but additionally signals that the analyzer shells out to a third-party
///   tool. The engine treats the two identically today; the discriminant
///   exists so future per-tool result caching can target only `ExternalTool`
///   analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerKind {
    /// Per-file analysis via `analyze_file`.
    FileLevel,
    /// Project-wide analysis via `analyze_project`. `analyze_file` is skipped.
    ProjectLevel,
    /// Same dispatch as `ProjectLevel`; signals an external-tool adapter.
    ExternalTool,
}

/// An analyzer that inspects source files or the whole project and emits
/// [`crate::finding::Finding`]s.
///
/// Cross-language analyzers consume only the [`crate::index::SemanticIndex`];
/// language-specific ones may additionally call
/// [`crate::parsed::ParsedFile::native`] to inspect the native AST.
pub trait Analyzer: Send + Sync {
    /// Returns the unique identifier of this analyzer instance.
    fn id(&self) -> AnalyzerId;

    /// Returns the quality dimension addressed by this analyzer.
    fn dimension(&self) -> Dimension;

    /// Returns the set of languages this analyzer supports.
    fn supported_languages(&self) -> SupportedLanguages;

    /// Returns the static metadata for every rule this analyzer can emit.
    fn rules(&self) -> &[RuleMeta];

    /// Returns the dispatch kind. Default is [`AnalyzerKind::FileLevel`].
    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::FileLevel
    }

    /// Analyses a single parsed file and returns zero or more findings.
    ///
    /// This method is called once per file, potentially from a `rayon` worker
    /// thread.  Implementors must be `Send + Sync`.
    fn analyze_file(&self, ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding>;

    /// Analyses the whole project and returns zero or more findings.
    ///
    /// Called after all per-file analyses are complete. The default
    /// implementation returns an empty vector; override for project-wide rules
    /// (e.g. cyclic dependency detection).
    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, _project: &Project) -> Vec<Finding> {
        Vec::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::config::Config;
    use crate::finding::Finding;
    use crate::id::{AnalyzerId, LanguageId};
    use crate::language::{Language as _, tests::MockLanguage};
    use crate::parsed::ParsedFile;
    use crate::source::SourceFile;
    use crate::span::{ByteOffset, LineCol, Location, Span};

    /// A do-nothing analyzer that emits a configurable set of pre-built findings.
    pub(crate) struct MockAnalyzer {
        /// Analyzer identifier.
        pub id: AnalyzerId,
        /// Dimension reported by this mock.
        pub dimension: Dimension,
        /// Pre-built findings to return from `analyze_file`.
        pub findings: Vec<Finding>,
    }

    impl Analyzer for MockAnalyzer {
        fn id(&self) -> AnalyzerId {
            self.id.clone()
        }

        fn dimension(&self) -> Dimension {
            self.dimension.clone()
        }

        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }

        fn rules(&self) -> &[RuleMeta] {
            &[]
        }

        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
            self.findings.clone()
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn supported_languages_all_supports_any() {
        let sl = SupportedLanguages::All;
        assert!(sl.supports(LanguageId("rust")));
        assert!(sl.supports(LanguageId("python")));
    }

    #[test]
    fn supported_languages_only() {
        let sl = SupportedLanguages::Only(smallvec::smallvec![LanguageId("rust")]);
        assert!(sl.supports(LanguageId("rust")));
        assert!(!sl.supports(LanguageId("python")));
    }

    #[test]
    fn dimension_display() {
        assert_eq!(Dimension::Maintainability.to_string(), "maintainability");
        assert_eq!(Dimension::Security.to_string(), "security");
        assert_eq!(
            Dimension::Custom("performance".to_string()).to_string(),
            "performance"
        );
    }

    #[test]
    fn severity_serde_round_trip() {
        let s = Severity::High;
        let json = serde_json::to_string(&s).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn mock_analyzer_returns_findings() {
        let finding = Finding {
            analyzer: AnalyzerId::new("mock"),
            dimension: Dimension::Maintainability,
            rule_id: "MOCK001".to_string(),
            severity: Severity::Low,
            message: "mock finding".to_string(),
            location: Location {
                file: PathBuf::from("a.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(1)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        };

        let analyzer = MockAnalyzer {
            id: AnalyzerId::new("mock"),
            dimension: Dimension::Maintainability,
            findings: vec![finding],
        };

        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let source = Arc::new(SourceFile::new("a.rs", b"fn x() {}".to_vec()));
        let lang = MockLanguage {
            id: LanguageId("mock"),
            exts: &["rs"],
        };
        let pf = lang.parse(source).unwrap();
        let results = analyzer.analyze_file(&ctx, &pf);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "MOCK001");
    }

    // ── Task 2: Dimension::Custom(String) serde round-trips ──────────────────

    #[test]
    fn custom_dimension_serializes_to_raw_string() {
        let d = Dimension::Custom("performance".to_string());
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, r#""performance""#);
    }

    #[test]
    fn custom_dimension_deserializes_from_unknown_string() {
        let d: Dimension = serde_json::from_str(r#""performance""#).unwrap();
        assert_eq!(d, Dimension::Custom("performance".to_string()));
    }

    #[test]
    fn custom_dimension_round_trips_through_json() {
        let original = Dimension::Custom("my-custom-dim".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let recovered: Dimension = serde_json::from_str(&json).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn builtin_dimensions_still_deserialize_correctly() {
        let cases = [
            (r#""maintainability""#, Dimension::Maintainability),
            (r#""security""#, Dimension::Security),
            (r#""complexity""#, Dimension::Complexity),
            (r#""documentation""#, Dimension::Documentation),
            (r#""test_smell""#, Dimension::TestSmell),
        ];
        for (json, expected) in cases {
            let got: Dimension = serde_json::from_str(json).unwrap();
            assert_eq!(got, expected, "failed for {json}");
        }
    }

    // ── Task 1: Dimension ordering is stable ─────────────────────────────────

    #[test]
    fn dimension_ord_is_stable() {
        // Derived Ord follows variant declaration order.
        assert!(Dimension::Maintainability < Dimension::Security);
        assert!(Dimension::Security < Dimension::Complexity);
        assert!(Dimension::Complexity < Dimension::Documentation);
        assert!(Dimension::Documentation < Dimension::TestSmell);
        assert!(Dimension::TestSmell < Dimension::Custom("a".to_string()));
        // Lexicographic within Custom.
        assert!(Dimension::Custom("a".to_string()) < Dimension::Custom("b".to_string()));
    }
}
