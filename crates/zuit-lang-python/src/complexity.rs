//! Cyclomatic and cognitive complexity counters for Python functions.
//!
//! # Cyclomatic complexity rules (Python)
//!
//! Starting value: 1 (baseline — every function has at least one path).
//!
//! +1 for each of:
//! - `if` statement (the initial `if` test; each `elif` branch is a separate
//!   `If` node in the rustpython AST after lowering, so each also counts +1).
//! - `elif` / `else` branches represented as nested `if` in `orelse`.
//! - `while` loop.
//! - `for` loop (including async for).
//! - `with` statement (including async with).
//! - Each `except` handler in a `try` block beyond the first.
//!   Rationale: the first path through the `try` body is already counted by
//!   the baseline; each additional handler adds one more.
//! - `BoolOp` with operator `And` or `Or`: each **occurrence** of `and`/`or`
//!   adds one (i.e., `a and b and c` = +2 because there are 2 operators).
//! - `if` clause inside a comprehension (`[x for x in y if cond]`).
//!
//! # Cognitive complexity rules (Sonar variant)
//!
//! Structural increments (each adds the **current nesting depth + 1**):
//! - `if` (and each `elif`/`else` branch).
//! - `for` / `async for`.
//! - `while`.
//! - `with` / `async with`.
//! - `try` / each `except` handler.
//! - Nested function definitions (lambda counts as +1 flat, not structural).
//!
//! Flat increments (always +1, regardless of nesting):
//! - Each `and` / `or` operator occurrence.
//! - Comprehension `if` clause.
//! - `break` / `continue`.
//! - `lambda` expression (treated as a flat +1 for an anonymous callable).
//!
//! Nesting is increased by: `if` (body), `for`, `while`, `with`, `try`,
//! `except` handler body, nested function/class definition body.

use rustpython_parser::ast::{Comprehension, Expr, Stmt};

use zuit_core::ComplexityMetrics;

// ── public entry points ──────────────────────────────────────────────────────

/// Computes [`ComplexityMetrics`] for the body of a regular or async function.
pub(crate) fn compute_function_complexity(body: &[Stmt]) -> ComplexityMetrics {
    let mut counter = ComplexityCounter::new();
    // Baseline cyclomatic = 1.
    counter.cyclomatic = 1;
    counter.walk_stmts(body, 0);
    ComplexityMetrics {
        cyclomatic: counter.cyclomatic,
        cognitive: counter.cognitive,
        max_nesting: counter.max_nesting,
        returns: counter.returns,
    }
}

/// Computes [`ComplexityMetrics`] for a lambda expression body.
pub(crate) fn compute_lambda_complexity(body: &Expr) -> ComplexityMetrics {
    let mut counter = ComplexityCounter::new();
    counter.cyclomatic = 1;
    counter.walk_expr(body, 0);
    ComplexityMetrics {
        cyclomatic: counter.cyclomatic,
        cognitive: counter.cognitive,
        max_nesting: counter.max_nesting,
        returns: counter.returns,
    }
}

// ── internal counter ─────────────────────────────────────────────────────────

struct ComplexityCounter {
    cyclomatic: u32,
    cognitive: u32,
    max_nesting: u32,
    returns: u32,
}

impl ComplexityCounter {
    fn new() -> Self {
        Self {
            cyclomatic: 0,
            cognitive: 0,
            max_nesting: 0,
            returns: 0,
        }
    }

    fn update_max_nesting(&mut self, depth: u32) {
        if depth > self.max_nesting {
            self.max_nesting = depth;
        }
    }

    // ── statement walker ─────────────────────────────────────────────────

    fn walk_stmts(&mut self, stmts: &[Stmt], depth: u32) {
        for stmt in stmts {
            self.walk_stmt(stmt, depth);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn walk_stmt(&mut self, stmt: &Stmt, depth: u32) {
        self.update_max_nesting(depth);
        match stmt {
            Stmt::If(s) => {
                // Cyclomatic: +1 for the `if` test.
                self.cyclomatic += 1;
                // Cognitive: structural, weighted by nesting.
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);

                // `elif` / `else` chains are represented as a single `Stmt::If`
                // inside `orelse` (elif) or a plain list (else).
                self.walk_orelse(&s.orelse, depth);
            }
            Stmt::While(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);
                // `else` on a while loop.
                if !s.orelse.is_empty() {
                    self.walk_stmts(&s.orelse, depth + 1);
                }
            }
            Stmt::For(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);
                if !s.orelse.is_empty() {
                    self.walk_stmts(&s.orelse, depth + 1);
                }
            }
            Stmt::AsyncFor(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);
                if !s.orelse.is_empty() {
                    self.walk_stmts(&s.orelse, depth + 1);
                }
            }
            Stmt::With(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);
            }
            Stmt::AsyncWith(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);
            }
            Stmt::Try(s) => {
                // The `try` body itself is not a branching construct for
                // cyclomatic (the baseline covers the happy path).
                // Each `except` handler adds +1.
                self.cognitive += depth + 1; // try block structural increment
                self.walk_stmts(&s.body, depth + 1);
                for (i, handler) in s.handlers.iter().enumerate() {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                    // First handler: cyclomatic does NOT get +1 (the baseline
                    // covers the try-body path). Second and beyond get +1.
                    if i > 0 {
                        self.cyclomatic += 1;
                    }
                    self.cognitive += depth + 1; // except handler structural
                    self.walk_stmts(&h.body, depth + 1);
                }
                if !s.orelse.is_empty() {
                    self.walk_stmts(&s.orelse, depth + 1);
                }
                if !s.finalbody.is_empty() {
                    self.walk_stmts(&s.finalbody, depth + 1);
                }
            }
            Stmt::TryStar(s) => {
                self.cognitive += depth + 1;
                self.walk_stmts(&s.body, depth + 1);
                for (i, handler) in s.handlers.iter().enumerate() {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                    if i > 0 {
                        self.cyclomatic += 1;
                    }
                    self.cognitive += depth + 1;
                    self.walk_stmts(&h.body, depth + 1);
                }
                if !s.orelse.is_empty() {
                    self.walk_stmts(&s.orelse, depth + 1);
                }
                if !s.finalbody.is_empty() {
                    self.walk_stmts(&s.finalbody, depth + 1);
                }
            }
            Stmt::Return(s) => {
                self.returns += 1;
                if let Some(v) = &s.value {
                    self.walk_expr(v, depth);
                }
            }
            Stmt::Break(_) | Stmt::Continue(_) => {
                // Cognitive +1 flat for break/continue.
                self.cognitive += 1;
            }
            Stmt::FunctionDef(f) => {
                // Nested function: cognitive structural increment.
                self.cognitive += depth + 1;
                // Walk its body at increased depth.
                self.walk_stmts(&f.body, depth + 1);
            }
            Stmt::AsyncFunctionDef(f) => {
                self.cognitive += depth + 1;
                self.walk_stmts(&f.body, depth + 1);
            }
            Stmt::Expr(s) => {
                self.walk_expr(&s.value, depth);
            }
            Stmt::Assign(s) => {
                self.walk_expr(&s.value, depth);
            }
            Stmt::AugAssign(s) => {
                self.walk_expr(&s.value, depth);
            }
            Stmt::AnnAssign(s) => {
                if let Some(v) = &s.value {
                    self.walk_expr(v, depth);
                }
            }
            // Other statement kinds don't add complexity.
            _ => {}
        }
    }

    /// Walk an `orelse` list, which in the Python AST contains either a single
    /// `Stmt::If` (representing `elif`) or plain statements (representing `else`).
    fn walk_orelse(&mut self, orelse: &[Stmt], depth: u32) {
        if orelse.is_empty() {
            return;
        }
        // `elif` is represented as a single `If` inside `orelse`.
        if orelse.len() == 1
            && let Stmt::If(inner_if) = &orelse[0]
        {
            // `elif`: cyclomatic +1 for the condition, cognitive structural.
            self.cyclomatic += 1;
            self.cognitive += depth + 1;
            self.walk_stmts(&inner_if.body, depth + 1);
            self.walk_orelse(&inner_if.orelse, depth);
            return;
        }
        // Plain `else` body — no additional cyclomatic, but walk the body.
        self.walk_stmts(orelse, depth + 1);
    }

    // ── expression walker ─────────────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    fn walk_expr(&mut self, expr: &Expr, depth: u32) {
        match expr {
            Expr::BoolOp(e) => {
                // Each `and`/`or` operator occurrence: cyclomatic +1, cognitive +1 flat.
                // `values.len()` operands means `values.len() - 1` operators.
                // values.len() is bounded by source file size, fits in u32.
                #[allow(clippy::cast_possible_truncation)]
                let ops = e.values.len().saturating_sub(1) as u32;
                self.cyclomatic += ops;
                self.cognitive += ops;
                for v in &e.values {
                    self.walk_expr(v, depth);
                }
            }
            Expr::IfExp(e) => {
                // Ternary `x if cond else y`: cyclomatic +1.
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_expr(&e.test, depth);
                self.walk_expr(&e.body, depth + 1);
                self.walk_expr(&e.orelse, depth + 1);
            }
            Expr::Lambda(lam) => {
                // Lambda inside an expression: flat cognitive +1.
                self.cognitive += 1;
                self.walk_expr(&lam.body, depth + 1);
            }
            Expr::ListComp(e) => {
                self.walk_comprehension_generators(&e.generators, depth);
                self.walk_expr(&e.elt, depth);
            }
            Expr::SetComp(e) => {
                self.walk_comprehension_generators(&e.generators, depth);
                self.walk_expr(&e.elt, depth);
            }
            Expr::GeneratorExp(e) => {
                self.walk_comprehension_generators(&e.generators, depth);
                self.walk_expr(&e.elt, depth);
            }
            Expr::DictComp(e) => {
                self.walk_comprehension_generators(&e.generators, depth);
                self.walk_expr(&e.key, depth);
                self.walk_expr(&e.value, depth);
            }
            Expr::Call(e) => {
                self.walk_expr(&e.func, depth);
                for arg in &e.args {
                    self.walk_expr(arg, depth);
                }
                for kw in &e.keywords {
                    self.walk_expr(&kw.value, depth);
                }
            }
            Expr::BinOp(e) => {
                self.walk_expr(&e.left, depth);
                self.walk_expr(&e.right, depth);
            }
            Expr::UnaryOp(e) => {
                self.walk_expr(&e.operand, depth);
            }
            Expr::Attribute(e) => {
                self.walk_expr(&e.value, depth);
            }
            Expr::Subscript(e) => {
                self.walk_expr(&e.value, depth);
                self.walk_expr(&e.slice, depth);
            }
            Expr::Starred(e) => {
                self.walk_expr(&e.value, depth);
            }
            Expr::List(e) => {
                for elt in &e.elts {
                    self.walk_expr(elt, depth);
                }
            }
            Expr::Tuple(e) => {
                for elt in &e.elts {
                    self.walk_expr(elt, depth);
                }
            }
            Expr::Dict(e) => {
                for k in e.keys.iter().flatten() {
                    self.walk_expr(k, depth);
                }
                for v in &e.values {
                    self.walk_expr(v, depth);
                }
            }
            Expr::Set(e) => {
                for elt in &e.elts {
                    self.walk_expr(elt, depth);
                }
            }
            Expr::Yield(e) => {
                if let Some(v) = &e.value {
                    self.walk_expr(v, depth);
                }
            }
            Expr::YieldFrom(e) => {
                self.walk_expr(&e.value, depth);
            }
            Expr::Await(e) => {
                self.walk_expr(&e.value, depth);
            }
            Expr::Compare(e) => {
                self.walk_expr(&e.left, depth);
                for comp in &e.comparators {
                    self.walk_expr(comp, depth);
                }
            }
            Expr::NamedExpr(e) => {
                self.walk_expr(&e.value, depth);
            }
            // Leaves: Name, Constant, JoinedStr, FormattedValue, Slice — no branching.
            _ => {}
        }
    }

    /// Walk comprehension generators, counting `if` clauses.
    fn walk_comprehension_generators(&mut self, generators: &[Comprehension], depth: u32) {
        for comp in generators {
            self.walk_expr(&comp.iter, depth);
            // Each `if` clause in a comprehension: cyclomatic +1, cognitive +1 flat.
            for cond in &comp.ifs {
                self.cyclomatic += 1;
                self.cognitive += 1;
                self.walk_expr(cond, depth);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustpython_parser::{Parse, ast::ModModule};

    fn complexity_of(src: &str) -> ComplexityMetrics {
        let module = ModModule::parse(src, "<test>").expect("parse failed");
        for stmt in &module.body {
            if let Stmt::FunctionDef(f) = stmt {
                return compute_function_complexity(&f.body);
            }
            if let Stmt::AsyncFunctionDef(f) = stmt {
                return compute_function_complexity(&f.body);
            }
        }
        panic!("no function found in source");
    }

    #[test]
    fn cyclomatic_baseline_is_one() {
        let m = complexity_of("def f():\n    pass\n");
        assert_eq!(m.cyclomatic, 1, "baseline should be 1");
    }

    #[test]
    fn cyclomatic_if_adds_one() {
        // baseline 1 + one if = 2; but we want to test exact value of 3
        let m =
            complexity_of("def f(x):\n    if x > 0:\n        pass\n    if x < 0:\n        pass\n");
        assert_eq!(m.cyclomatic, 3, "two ifs → cyclomatic 3");
    }

    #[test]
    fn cyclomatic_three() {
        // if + elif = 2 branches + baseline 1 = 3
        let src = "def f(x):\n    if x > 0:\n        return 1\n    elif x < 0:\n        return -1\n    return 0\n";
        let m = complexity_of(src);
        assert_eq!(m.cyclomatic, 3, "if+elif → cyclomatic 3");
    }

    #[test]
    fn cyclomatic_seven() {
        // baseline 1 + 6 branches = 7
        let src = "\
def f(a, b, c):
    if a:
        if b:
            if c:
                return 1
            else:
                return 2
        elif b > 5:
            return 3
    elif a > 5:
        if b:
            return 4
        return 5
    return 6
";
        let m = complexity_of(src);
        assert_eq!(
            m.cyclomatic, 7,
            "expected cyclomatic 7, got {}",
            m.cyclomatic
        );
    }

    #[test]
    fn bool_op_adds_to_cyclomatic() {
        // baseline 1 + `and` (1 op) + `or` (1 op) = 3
        let m = complexity_of("def f(a, b, c):\n    return a and b or c\n");
        assert_eq!(m.cyclomatic, 3);
    }

    #[test]
    fn returns_counted() {
        let m = complexity_of("def f(x):\n    if x:\n        return 1\n    return 0\n");
        assert_eq!(m.returns, 2);
    }

    #[test]
    fn comprehension_if_adds_cyclomatic() {
        let m = complexity_of("def f(xs):\n    return [x for x in xs if x > 0]\n");
        // baseline 1 + comprehension if 1 = 2
        assert_eq!(m.cyclomatic, 2);
    }

    #[test]
    fn while_for_with_add_cyclomatic() {
        let src = "\
def f(xs):
    while True:
        break
    for x in xs:
        pass
    with open('f') as fp:
        pass
";
        let m = complexity_of(src);
        // baseline 1 + while 1 + for 1 + with 1 = 4
        assert_eq!(m.cyclomatic, 4);
    }

    #[test]
    fn try_except_adds_per_handler_beyond_first() {
        // try + 1 handler (first) = 0 extra; 2nd handler = +1 → total baseline 1 + 1 = 2
        let src = "\
def f():
    try:
        pass
    except ValueError:
        pass
    except TypeError:
        pass
";
        let m = complexity_of(src);
        assert_eq!(m.cyclomatic, 2, "one extra handler → cyclomatic 2");
    }
}
