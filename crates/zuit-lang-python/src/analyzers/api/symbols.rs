//! Public API extraction from a parsed Python `ModModule`.
//!
//! `extract_public_api` walks top-level statements in a `ModModule` and
//! collects public symbols (functions, async functions, classes).
//!
//! ## Visibility rules
//!
//! 1. If the module contains a top-level `__all__ = [...]` assignment whose
//!    right-hand side is a list of string literals, those names are used as the
//!    authoritative public set.  Private-prefix names that appear in `__all__`
//!    **are** included.
//! 2. Otherwise, any top-level `def`/`async def`/`class` whose name does **not**
//!    start with `_` is treated as public.

use rustpython_parser::ast::{Expr, ModModule, Stmt};

use super::{FunctionSig, PublicApi};

/// Extracts public symbols from a single parsed module, accumulating them into
/// `api`.
///
/// Designed to be called once per file; results across files are merged into
/// the same `api` struct.
pub(crate) fn collect_public_api(module: &ModModule, api: &mut PublicApi) {
    // Step 1: check for `__all__`.
    let all_names = extract_dunder_all(module);

    let use_all = all_names.is_some();
    let all_set: std::collections::HashSet<String> = all_names.unwrap_or_default();

    for stmt in &module.body {
        match stmt {
            Stmt::FunctionDef(f) => {
                let name = f.name.as_str().to_string();
                if is_public(&name, use_all, &all_set) {
                    let sig = sig_from_args(&f.args);
                    api.functions.insert(name, sig);
                }
            }
            Stmt::AsyncFunctionDef(f) => {
                let name = f.name.as_str().to_string();
                if is_public(&name, use_all, &all_set) {
                    let sig = sig_from_args(&f.args);
                    api.functions.insert(name, sig);
                }
            }
            Stmt::ClassDef(c) => {
                let name = c.name.as_str().to_string();
                if is_public(&name, use_all, &all_set) {
                    api.classes.insert(name);
                }
            }
            _ => {}
        }
    }
}

/// Extracts `__all__` as a set of strings, if present and parseable.
fn extract_dunder_all(module: &ModModule) -> Option<std::collections::HashSet<String>> {
    for stmt in &module.body {
        if let Stmt::Assign(a) = stmt {
            // Look for `__all__ = [...]` or `__all__ = (...)`
            let is_all = a.targets.iter().any(|t| {
                if let Expr::Name(n) = t {
                    n.id.as_str() == "__all__"
                } else {
                    false
                }
            });
            if !is_all {
                continue;
            }
            let names = extract_string_list(&a.value)?;
            return Some(names.into_iter().collect());
        }
    }
    None
}

/// Extracts a `Vec<String>` from a list/tuple of string constants.
fn extract_string_list(expr: &Expr) -> Option<Vec<String>> {
    let elts = match expr {
        Expr::List(l) => &l.elts,
        Expr::Tuple(t) => &t.elts,
        _ => return None,
    };
    let mut names = Vec::with_capacity(elts.len());
    for elt in elts {
        if let Expr::Constant(c) = elt {
            if let rustpython_parser::ast::Constant::Str(s) = &c.value {
                names.push(s.clone());
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(names)
}

/// Determines whether `name` is public.
///
/// When `use_all` is `true`, visibility is determined entirely by membership in
/// `all_set`.  Otherwise, any name not starting with `_` is public.
fn is_public(name: &str, use_all: bool, all_set: &std::collections::HashSet<String>) -> bool {
    if use_all {
        all_set.contains(name)
    } else {
        !name.starts_with('_')
    }
}

/// Builds a [`FunctionSig`] from a rustpython `Arguments` node.
fn sig_from_args(args: &rustpython_parser::ast::Arguments) -> FunctionSig {
    FunctionSig {
        posonly: args.posonlyargs.len(),
        args: args.args.len(),
        kwonly: args.kwonlyargs.len(),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustpython_parser::Parse;
    use rustpython_parser::ast::ModModule;

    fn parse_api(src: &str) -> PublicApi {
        let module = ModModule::parse(src, "<test>").expect("parse failed");
        let mut api = PublicApi::default();
        collect_public_api(&module, &mut api);
        api
    }

    #[test]
    fn collects_top_level_functions() {
        let api = parse_api("def hello(): pass\ndef world(a, b): pass\n");
        assert!(api.functions.contains_key("hello"));
        assert!(api.functions.contains_key("world"));
        assert_eq!(api.functions.len(), 2);
    }

    #[test]
    fn skips_private_functions() {
        let api = parse_api("def _internal(): pass\ndef public(): pass\n");
        assert!(!api.functions.contains_key("_internal"));
        assert!(api.functions.contains_key("public"));
    }

    #[test]
    fn includes_private_if_in_dunder_all() {
        let src = "__all__ = ['_internal']\ndef _internal(): pass\n";
        let api = parse_api(src);
        assert!(
            api.functions.contains_key("_internal"),
            "__all__ should override underscore filter"
        );
    }

    #[test]
    fn excludes_public_fn_not_in_dunder_all() {
        let src = "__all__ = ['exported']\ndef exported(): pass\ndef not_exported(): pass\n";
        let api = parse_api(src);
        assert!(api.functions.contains_key("exported"));
        assert!(!api.functions.contains_key("not_exported"));
    }

    #[test]
    fn captures_arity_correctly() {
        let api = parse_api("def f(a, b, c): pass\n");
        let sig = api.functions.get("f").expect("f should be present");
        assert_eq!(sig.args, 3);
        assert_eq!(sig.total_arity(), 3);
    }

    #[test]
    fn captures_posonly_and_kwonly() {
        // def f(a, /, b, *, c): pass
        let api = parse_api("def f(a, /, b, *, c): pass\n");
        let sig = api.functions.get("f").expect("f should be present");
        assert_eq!(sig.posonly, 1);
        assert_eq!(sig.args, 1);
        assert_eq!(sig.kwonly, 1);
        assert_eq!(sig.total_arity(), 3);
    }

    #[test]
    fn collects_top_level_classes() {
        let api = parse_api("class Foo: pass\nclass Bar: pass\n");
        assert!(api.classes.contains("Foo"));
        assert!(api.classes.contains("Bar"));
    }

    #[test]
    fn skips_private_classes() {
        let api = parse_api("class _Private: pass\nclass Public: pass\n");
        assert!(!api.classes.contains("_Private"));
        assert!(api.classes.contains("Public"));
    }

    #[test]
    fn async_def_collected() {
        let api = parse_api("async def afunc(x): pass\n");
        assert!(api.functions.contains_key("afunc"));
        let sig = api.functions.get("afunc").unwrap();
        assert_eq!(sig.args, 1);
    }
}
