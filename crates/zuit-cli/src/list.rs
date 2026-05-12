//! Implementation of the `zuit list` subcommands.
//!
//! Two sub-commands are supported:
//! - `zuit list languages` — prints a table of known language IDs and extensions.
//! - `zuit list analyzers [--explain <rule_id>]` — prints analyzer metadata
//!   or a rule explanation.

use anyhow::{Result, bail};

use crate::cli::{ListAnalyzersArgs, ListCommand};
use crate::registry_builtin::build_registry;

/// A single row in the analyzer listing table.
struct AnalyzerRow {
    rule_id: String,
    dimension: String,
    languages: String,
    /// Pre-formatted CWE/OWASP taxonomy string (e.g. `"CWE-798, A07:2021"`).
    /// Empty for rules without a canonical mapping.
    taxonomy: String,
}

/// Runs the `list` subcommand and returns the desired exit code.
///
/// Always returns 0 unless `--explain` points to a rule that does not exist in
/// the registry at all (in that case we still return 0 and print what we can).
///
/// # Errors
///
/// Returns an error when `--explain` names a rule that is not registered.
pub fn run(cmd: ListCommand) -> Result<i32> {
    match cmd {
        ListCommand::Languages => Ok(list_languages()),
        ListCommand::Analyzers(args) => list_analyzers(&args),
        ListCommand::Plugins => crate::plugins::list(),
    }
}

/// Prints a table of registered languages and their file extensions.
fn list_languages() -> i32 {
    let registry = build_registry();
    let langs: Vec<_> = registry.languages().collect();

    if langs.is_empty() {
        println!("No languages registered.");
        return 0;
    }

    // Determine column widths.
    let id_width = langs
        .iter()
        .map(|l| l.id().0.len())
        .max()
        .unwrap_or(2)
        .max(8); // at least "LANGUAGE"
    let ext_width = langs
        .iter()
        .map(|l| l.extensions().join(", ").len())
        .max()
        .unwrap_or(6)
        .max(10); // at least "EXTENSIONS"

    // Header.
    println!(
        "{:<id_width$}  {:<ext_width$}",
        "LANGUAGE",
        "EXTENSIONS",
        id_width = id_width,
        ext_width = ext_width
    );
    println!("{}", "-".repeat(id_width + 2 + ext_width));

    for lang in langs {
        println!(
            "{:<id_width$}  {:<ext_width$}",
            lang.id().0,
            lang.extensions().join(", "),
            id_width = id_width,
            ext_width = ext_width
        );
    }

    0
}

/// Column widths for the analyzer table.
struct ColumnWidths {
    rule: usize,
    dimension: usize,
    language: usize,
    taxonomy: usize,
}

/// Builds a `Vec<AnalyzerRow>` from the registered analyzers.
fn build_analyzer_rows(analyzers: &[&dyn zuit_core::Analyzer]) -> Vec<AnalyzerRow> {
    let mut rows: Vec<AnalyzerRow> = Vec::new();
    for analyzer in analyzers {
        let dim = analyzer.dimension().to_string();
        let langs = match analyzer.supported_languages() {
            zuit_core::SupportedLanguages::All => "all".to_string(),
            zuit_core::SupportedLanguages::Only(ref ids) => {
                ids.iter().map(|id| id.0).collect::<Vec<_>>().join(", ")
            }
        };
        for rule in analyzer.rules() {
            let tax = rule
                .cwe
                .iter()
                .copied()
                .chain(rule.owasp.iter().copied())
                .collect::<Vec<_>>()
                .join(", ");
            rows.push(AnalyzerRow {
                rule_id: rule.id.to_string(),
                dimension: dim.clone(),
                languages: langs.clone(),
                taxonomy: tax,
            });
        }
    }
    rows
}

/// Computes the column widths needed to render `rows` in an aligned table.
fn compute_column_widths(rows: &[AnalyzerRow]) -> ColumnWidths {
    ColumnWidths {
        rule: rows
            .iter()
            .map(|r| r.rule_id.len())
            .max()
            .unwrap_or(0)
            .max(7),
        dimension: rows
            .iter()
            .map(|r| r.dimension.len())
            .max()
            .unwrap_or(0)
            .max(9),
        language: rows
            .iter()
            .map(|r| r.languages.len())
            .max()
            .unwrap_or(0)
            .max(9),
        taxonomy: rows
            .iter()
            .map(|r| r.taxonomy.len())
            .max()
            .unwrap_or(0)
            .max(8),
    }
}

/// Prints the header, separator, and data rows of the analyzer table.
fn print_analyzer_table(rows: &[AnalyzerRow], widths: &ColumnWidths) {
    let (rule_w, dim_w, lang_w, tax_w) = (
        widths.rule,
        widths.dimension,
        widths.language,
        widths.taxonomy,
    );
    println!(
        "{:<rule_w$}  {:<dim_w$}  {:<lang_w$}  {:<tax_w$}",
        "RULE_ID",
        "DIMENSION",
        "LANGUAGES",
        "TAXONOMY",
        rule_w = rule_w,
        dim_w = dim_w,
        lang_w = lang_w,
        tax_w = tax_w,
    );
    println!(
        "{}",
        "-".repeat(rule_w + 2 + dim_w + 2 + lang_w + 2 + tax_w)
    );
    for row in rows {
        println!(
            "{:<rule_w$}  {:<dim_w$}  {:<lang_w$}  {:<tax_w$}",
            row.rule_id,
            row.dimension,
            row.languages,
            row.taxonomy,
            rule_w = rule_w,
            dim_w = dim_w,
            lang_w = lang_w,
            tax_w = tax_w,
        );
    }
}

/// Prints a table of registered analyzers, or explains a specific rule.
fn list_analyzers(args: &ListAnalyzersArgs) -> Result<i32> {
    let registry = build_registry();
    let analyzers: Vec<_> = registry.analyzers().collect();

    // If --explain is requested, look up the rule and print its doc file.
    if let Some(ref rule_id) = args.explain {
        return explain_rule(rule_id, &analyzers);
    }

    if analyzers.is_empty() {
        println!("No analyzers registered.");
        return Ok(0);
    }

    let rows = build_analyzer_rows(&analyzers);

    if rows.is_empty() {
        println!("No rules registered.");
        return Ok(0);
    }

    let widths = compute_column_widths(&rows);
    print_analyzer_table(&rows, &widths);

    Ok(0)
}

/// Looks up `rule_id` among all registered analyzers and prints the
/// corresponding documentation from `docs/rules/<rule_id>.md` if present.
fn explain_rule(rule_id: &str, analyzers: &[&dyn zuit_core::Analyzer]) -> Result<i32> {
    // Find the rule metadata.
    let meta = analyzers
        .iter()
        .flat_map(|a| a.rules())
        .find(|r| r.id == rule_id);

    let Some(meta) = meta else {
        bail!("rule '{rule_id}' not found in any registered analyzer");
    };

    // Try to read the documentation file.
    let doc_path = std::path::Path::new(meta.doc_path);
    if let Ok(content) = std::fs::read_to_string(doc_path) {
        print!("{content}");
    } else {
        // Print what we know from the metadata, plus a note.
        println!("Rule: {}", meta.id);
        println!("Default severity: {:?}", meta.default_severity);
        println!("Documentation: {}", meta.doc_path);
        println!();
        eprintln!(
            "note: rule explanation file not found at {}",
            doc_path.display()
        );
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test: `list_languages` must not panic and must succeed.
    #[test]
    fn list_languages_runs() {
        assert_eq!(list_languages(), 0);
    }

    /// Smoke-test: `list_analyzers` must not panic and must succeed.
    #[test]
    fn list_analyzers_runs() {
        let result = list_analyzers(&ListAnalyzersArgs { explain: None });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    /// An unknown `rule_id` should produce an error.
    #[test]
    fn explain_unknown_rule_errors() {
        let registry = build_registry();
        let analyzers: Vec<_> = registry.analyzers().collect();
        let result = explain_rule("NONEXISTENT-rule", &analyzers);
        assert!(result.is_err());
    }
}
