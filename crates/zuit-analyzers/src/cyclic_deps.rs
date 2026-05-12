//! `CPLX002-cyclic-deps` — detects cycles in the per-file import graph.
//!
//! # Algorithm
//!
//! 1. **Node assignment.** Every `ParsedFile` path becomes a node.  Nodes are
//!    assigned stable integer indices by sorting paths lexicographically first.
//!
//! 2. **Module-key map.** For each file path we derive lookup keys:
//!    - The full path with the extension stripped and directory separators
//!      replaced by `::` (e.g. `src/utils/fmt.py` → `src::utils::fmt`).
//!    - Every trailing suffix (e.g. `utils::fmt`, then `fmt`).
//!    - For relative JS/TS imports that begin with `./` or `../`, the basename
//!      of the target (e.g. `./b` → `b`, `../utils/fmt` → `fmt`).
//!
//!    All of these aliases point to the same node index in a `HashMap`.
//!    When two files produce the same alias the first one wins (shortest-path
//!    wins is stable because nodes are processed in lexicographic order).
//!
//! 3. **Edge building.** For each `Import.path` in each file we try to resolve
//!    it to an in-project node.  Imports that don't resolve (standard library,
//!    third-party) are silently ignored — this is a known limitation.
//!
//! 4. **Tarjan SCC.** A hand-rolled implementation finds all strongly-connected
//!    components.  An SCC of size > 1 is a cycle; size 1 with a self-loop is
//!    also a cycle.
//!
//! 5. **Finding emission.** One finding per SCC, anchored at the
//!    lexicographically smallest file in the SCC.  The message names all
//!    module keys in the cycle (sorted) so the output is deterministic.
//!
//! # Limitations
//!
//! - Cross-language imports (e.g. Python calling Rust via FFI) will never link.
//! - Standard-library and third-party imports are silently skipped because
//!   their paths don't match any in-project file.
//! - The alias matching is heuristic: a short module name (e.g. `fmt`) may
//!   collide with an unrelated file that happens to have the same stem.
//! - Rust `use crate::…` paths and `mod` declarations require a built crate
//!   graph that is not available at the `SemanticIndex` level.  Rust import
//!   detection is therefore limited to what `syn` populates in `index.imports`
//!   (top-level `use` items), and false-negatives are expected.

use std::collections::HashMap;
use std::path::Path;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Location, Span},
};

/// Rule ID for the cyclic-dependencies check.
pub const RULE_ID: &str = "CPLX002-cyclic-deps";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/CPLX002-cyclic-deps.md",
    cwe: &[],
    owasp: &[],
};

// ── Tarjan SCC ────────────────────────────────────────────────────────────────

/// State used by the Tarjan SCC algorithm.
struct TarjanState {
    /// Depth-first search discovery index for each node.
    index: Vec<Option<u32>>,
    /// The smallest discovery index reachable from each node (low-link value).
    low_link: Vec<u32>,
    /// Whether each node is currently on the DFS stack.
    on_stack: Vec<bool>,
    /// The DFS stack.
    stack: Vec<usize>,
    /// Next discovery index to assign.
    counter: u32,
    /// Collected SCCs (each is a list of node indices).
    sccs: Vec<Vec<usize>>,
}

impl TarjanState {
    fn new(n: usize) -> Self {
        Self {
            index: vec![None; n],
            low_link: vec![0; n],
            on_stack: vec![false; n],
            stack: Vec::new(),
            counter: 0,
            sccs: Vec::new(),
        }
    }
}

/// Runs Tarjan's SCC algorithm on `adj` (adjacency list, `adj[u]` = out-neighbours
/// of node `u`) and returns all SCCs.
///
/// Only non-trivial SCCs (size > 1, or size 1 with a self-loop) are returned.
#[must_use]
pub fn tarjan_sccs(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adj.len();
    let mut state = TarjanState::new(n);

    for v in 0..n {
        if state.index[v].is_none() {
            tarjan_visit(v, adj, &mut state);
        }
    }

    state.sccs
}

/// Recursive DFS visit for Tarjan's algorithm.
///
/// The recursion depth is bounded by the number of nodes in the graph, which
/// in practice equals the number of parsed source files.  For typical projects
/// this is well within stack limits; very large monorepos may need to convert
/// this to an explicit stack, but that is out of scope for v1.
fn tarjan_visit(v: usize, adj: &[Vec<usize>], state: &mut TarjanState) {
    let idx = state.counter;
    state.index[v] = Some(idx);
    state.low_link[v] = idx;
    state.counter += 1;
    state.stack.push(v);
    state.on_stack[v] = true;

    for &w in &adj[v] {
        if state.index[w].is_none() {
            tarjan_visit(w, adj, state);
            state.low_link[v] = state.low_link[v].min(state.low_link[w]);
        } else if state.on_stack[w] {
            let w_idx = state.index[w].expect("invariant: w was visited above");
            state.low_link[v] = state.low_link[v].min(w_idx);
        }
    }

    // If `v` is a root of an SCC, pop the component.
    if state.low_link[v] == state.index[v].expect("invariant: v was just assigned an index") {
        let mut scc = Vec::new();
        loop {
            let w = state
                .stack
                .pop()
                .expect("invariant: stack is non-empty while popping SCC");
            state.on_stack[w] = false;
            scc.push(w);
            if w == v {
                break;
            }
        }

        // Only keep non-trivial SCCs: size > 1, or size 1 with a self-loop.
        let is_nontrivial = scc.len() > 1 || scc.first().is_some_and(|&u| adj[u].contains(&u));
        if is_nontrivial {
            state.sccs.push(scc);
        }
    }
}

// ── module-key helpers ────────────────────────────────────────────────────────

/// Strips the file extension and replaces path separators with `::`.
///
/// `src/utils/fmt.py` → `src::utils::fmt`
///
/// Both forward-slash (`/`) and the platform `MAIN_SEPARATOR` (backslash on
/// Windows) are treated as separators so the result is the same on all
/// platforms.
fn path_to_module_key(path: &Path) -> String {
    let without_ext = path.with_extension("");
    // Split on the OS path separator and re-join with `::` so that both
    // Unix `/` and Windows `\` are handled uniformly without a consecutive
    // `str::replace` call.
    without_ext
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("::")
}

/// Returns all "suffix keys" for a full module key.
///
/// Given `src::utils::fmt` this returns `["src::utils::fmt", "utils::fmt", "fmt"]`.
fn suffix_keys(full_key: &str) -> Vec<String> {
    let parts: Vec<&str> = full_key.split("::").collect();
    (0..parts.len()).map(|i| parts[i..].join("::")).collect()
}

/// Normalises a JS/TS relative import path to the bare stem for alias lookup.
///
/// `./b`       → `b`
/// `./utils/fmt` → `fmt`  (shortest suffix — heuristic)
/// `../sibling`  → `sibling`
///
/// Returns `None` for absolute/third-party imports (no leading `./` or `../`).
fn js_relative_stem(import_path: &str) -> Option<String> {
    let stripped = import_path
        .strip_prefix("./")
        .or_else(|| import_path.strip_prefix("../"))?;
    // Use the last path component as the stem (remove any sub-path for `../a/b` → `b`).
    let stem = stripped.rsplit('/').next().unwrap_or(stripped);
    // Strip a `.ts` / `.js` extension if present in the import specifier.
    let stem = stem
        .strip_suffix(".ts")
        .or_else(|| stem.strip_suffix(".tsx"))
        .or_else(|| stem.strip_suffix(".js"))
        .or_else(|| stem.strip_suffix(".mjs"))
        .unwrap_or(stem);
    Some(stem.to_string())
}

// ── analyzer ──────────────────────────────────────────────────────────────────

/// Analyzer that detects import cycles across all in-project files.
#[derive(Debug, Default)]
pub struct CyclicDepsAnalyzer;

impl Analyzer for CyclicDepsAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Complexity
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
        // All logic lives in `analyze_project`.
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        if project.files.is_empty() {
            return vec![];
        }

        // 1. Sort files by path for stable node ordering.
        let mut files: Vec<&ParsedFile> = project.files.iter().collect();
        files.sort_by_key(|f| &f.source().path);

        // 2. Build the module-key → node-index map.
        let (key_to_node, node_keys) = build_node_keys(&files);

        // 3. Build the adjacency list.
        let adj = build_adjacency(&files, &key_to_node);

        // 4. Run Tarjan SCC.
        let sccs = tarjan_sccs(&adj);

        // 5. Emit one finding per non-trivial SCC (sorted for determinism).
        emit_cycle_findings(sccs, &files, &node_keys)
    }
}

/// Builds the module-key → node-index map and the canonical key list for each node.
///
/// Returns `(key_to_node, node_keys)` where `key_to_node` maps every module-key
/// alias (full path + all trailing suffixes) to the corresponding node index and
/// `node_keys` holds the canonical full-path-derived key for each node.
fn build_node_keys(files: &[&ParsedFile]) -> (HashMap<String, usize>, Vec<String>) {
    let n = files.len();
    let mut key_to_node: HashMap<String, usize> = HashMap::new();
    let mut node_keys: Vec<String> = Vec::with_capacity(n);

    for (idx, file) in files.iter().enumerate() {
        let path = &file.source().path;
        let full_key = path_to_module_key(path);
        node_keys.push(full_key.clone());

        // Register all suffix keys; first one written wins (shortest-path wins
        // because nodes are processed in lexicographic order).
        for suffix in suffix_keys(&full_key) {
            key_to_node.entry(suffix).or_insert(idx);
        }
    }

    (key_to_node, node_keys)
}

/// Builds the directed adjacency list from import edges, resolving each import
/// path via `key_to_node`.
///
/// Unresolvable imports (standard-library, third-party) are silently skipped.
fn build_adjacency(files: &[&ParsedFile], key_to_node: &HashMap<String, usize>) -> Vec<Vec<usize>> {
    let n = files.len();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (src_idx, file) in files.iter().enumerate() {
        for import in &file.index().imports {
            // Try the import path as-is first.
            if let Some(&dst) = key_to_node.get(&import.path) {
                if dst != src_idx && !adj[src_idx].contains(&dst) {
                    adj[src_idx].push(dst);
                }
                continue;
            }

            // Try treating it as a JS/TS relative import.
            if let Some(stem) = js_relative_stem(&import.path)
                && let Some(&dst) = key_to_node.get(&stem)
                && dst != src_idx
                && !adj[src_idx].contains(&dst)
            {
                adj[src_idx].push(dst);
            }
        }
    }

    adj
}

/// Converts Tarjan SCC output into `Finding`s, one per non-trivial cycle.
///
/// Each finding is anchored at the lexicographically smallest file in the SCC.
/// The returned list is sorted for determinism.
fn emit_cycle_findings(
    sccs: Vec<Vec<usize>>,
    files: &[&ParsedFile],
    node_keys: &[String],
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    for mut scc in sccs {
        // Sort node indices; the smallest index corresponds to the lex-smallest
        // file (because files were sorted by path before node assignment).
        scc.sort_unstable();

        let anchor_idx = scc[0];
        let anchor_file = files[anchor_idx];
        let anchor_path = anchor_file.source().path.clone();

        // Build the sorted list of module keys for the message.
        let mut cycle_keys: Vec<&str> = scc.iter().map(|&i| node_keys[i].as_str()).collect();
        cycle_keys.sort_unstable();
        let key_list = cycle_keys.join(", ");
        let n_cycle = scc.len();

        let span = Span::new(ByteOffset(0), ByteOffset(0));
        let lc = LineCol::new(1, 1);

        findings.push(Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Complexity,
            rule_id: RULE_ID.to_string(),
            severity: Severity::High,
            message: format!("file is part of an import cycle of {n_cycle} modules: {key_list}"),
            location: Location {
                file: anchor_path,
                span,
                start: lc,
                end: lc,
            },
            suggestion: Some(
                "Break the dependency cycle by extracting shared code into a new module \
                 that both sides depend on, or by inverting one of the dependencies."
                    .to_string(),
            ),
            references: vec![],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        });
    }

    // Sort findings for determinism (normally the engine does this, but
    // emitting them pre-sorted makes unit tests straightforward).
    findings.sort();
    findings
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Language, SourceFile};
    use std::path::PathBuf;
    use std::sync::Arc;

    // ── parse helpers ─────────────────────────────────────────────────────────

    fn python_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    fn js_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_js::JsLanguage
            .parse(src)
            .expect("js parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Tarjan unit tests ─────────────────────────────────────────────────────

    #[test]
    fn tarjan_three_cycle_detected() {
        // Graph: 0→1, 1→2, 2→0 — one SCC of size 3.
        let adj = vec![vec![1], vec![2], vec![0]];
        let sccs = tarjan_sccs(&adj);
        assert_eq!(sccs.len(), 1, "expected one SCC");
        assert_eq!(sccs[0].len(), 3, "expected SCC of size 3");
    }

    #[test]
    fn tarjan_linear_chain_no_cycle() {
        // Graph: 0→1, 1→2 — no back edge, no SCC.
        let adj = vec![vec![1], vec![2], vec![]];
        let sccs = tarjan_sccs(&adj);
        assert!(sccs.is_empty(), "linear chain should have no cycles");
    }

    #[test]
    fn tarjan_self_loop_detected() {
        // Graph: 0→0 (self-loop).
        let adj = vec![vec![0], vec![], vec![]];
        let sccs = tarjan_sccs(&adj);
        assert_eq!(sccs.len(), 1, "self-loop should be detected as a cycle");
        assert_eq!(sccs[0], vec![0]);
    }

    #[test]
    fn tarjan_two_separate_cycles() {
        // Graph: 0→1→0 and 2→3→2.
        let adj = vec![vec![1], vec![0], vec![3], vec![2]];
        let sccs = tarjan_sccs(&adj);
        assert_eq!(sccs.len(), 2, "expected two distinct SCCs");
    }

    #[test]
    fn tarjan_empty_graph() {
        let adj: Vec<Vec<usize>> = vec![];
        let sccs = tarjan_sccs(&adj);
        assert!(sccs.is_empty());
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_cyclic_deps_positive() {
        let a = include_str!("../../../fixtures/python/cyclic_deps/a.py");
        let b = include_str!("../../../fixtures/python/cyclic_deps/b.py");
        let c = include_str!("../../../fixtures/python/cyclic_deps/c.py");

        let files = vec![
            python_parse("fixtures/python/cyclic_deps/a.py", a),
            python_parse("fixtures/python/cyclic_deps/b.py", b),
            python_parse("fixtures/python/cyclic_deps/c.py", c),
        ];

        let root = PathBuf::from("fixtures/python/cyclic_deps");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = CyclicDepsAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX002 finding for Python cyclic fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings should have rule_id {RULE_ID}"
        );
        assert!(
            findings.iter().any(|f| f.message.contains("3 modules")),
            "expected a message about a 3-module cycle, got: {:#?}",
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_cyclic_deps_positive() {
        let a = include_str!("../../../fixtures/js/cyclic_deps/a.ts");
        let b = include_str!("../../../fixtures/js/cyclic_deps/b.ts");
        let c = include_str!("../../../fixtures/js/cyclic_deps/c.ts");

        let files = vec![
            js_parse("fixtures/js/cyclic_deps/a.ts", a),
            js_parse("fixtures/js/cyclic_deps/b.ts", b),
            js_parse("fixtures/js/cyclic_deps/c.ts", c),
        ];

        let root = PathBuf::from("fixtures/js/cyclic_deps");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = CyclicDepsAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX002 finding for JS cyclic fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings should have rule_id {RULE_ID}"
        );
        assert!(
            findings.iter().any(|f| f.message.contains("3 modules")),
            "expected a message about a 3-module cycle, got: {:#?}",
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_healthy_no_cycles() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let files = vec![python_parse("fixtures/python/healthy/main.py", source)];

        let root = PathBuf::from("fixtures/python/healthy");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = CyclicDepsAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "expected 0 CPLX002 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── module key helpers ────────────────────────────────────────────────────

    #[test]
    fn path_to_module_key_strips_ext_and_replaces_sep() {
        let p = Path::new("src/utils/fmt.py");
        let key = path_to_module_key(p);
        assert!(
            key.contains("fmt") && !key.contains(".py"),
            "unexpected key: {key}"
        );
    }

    #[test]
    fn suffix_keys_generates_all_suffixes() {
        let keys = suffix_keys("a::b::c");
        assert_eq!(keys, vec!["a::b::c", "b::c", "c"]);
    }

    #[test]
    fn js_relative_stem_extracts_basename() {
        assert_eq!(js_relative_stem("./b"), Some("b".to_string()));
        assert_eq!(js_relative_stem("../utils/fmt"), Some("fmt".to_string()));
        assert_eq!(js_relative_stem("lodash"), None); // third-party
    }
}
