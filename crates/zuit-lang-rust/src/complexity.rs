//! Per-function complexity metrics for Rust source.
//!
//! # Cyclomatic complexity rules (Rust)
//!
//! Cyclomatic complexity starts at 1 and adds +1 for each:
//! - `if` expression (including `if let`)
//! - `else if` arm (each additional `else if` is a separate `if` node)
//! - `while` / `while let` loop
//! - `for` loop
//! - `loop` with a conditional `break` expression (each `break <expr>` counts)
//! - Each `match` arm **beyond the first** (so a 3-arm match adds +2)
//! - `?` operator (each `ExprTry` in the body)
//! - Short-circuit `&&` and `||` binary operators (each occurrence adds +1)
//!
//! # Cognitive complexity rules (Rust — Sonar variant)
//!
//! Cognitive complexity measures *understandability* rather than path count.
//! The Sonar variant differs from cyclomatic in two ways:
//!
//! 1. **Nesting bonus**: control-flow structures that are already inside another
//!    control-flow structure add an extra +1 per nesting level on top of the
//!    base +1.  Nesting increments for: `if` (incl. `if let`), `while` /
//!    `while let`, `for`, `loop`, and `match`.
//! 2. **`&&` / `||` chains**: consecutive `&&` or `||` operators in a single
//!    boolean chain count as **one** +1 regardless of how many operators appear.
//!    A *chain* is broken when the operator type changes or a non-boolean
//!    sub-expression is encountered.  (Cyclomatic counts every occurrence.)
//!
//! Structural jumps (`break`, `continue`, `return`, `?`) each add +1 at the
//! base level with no nesting bonus.

use syn::visit::Visit;

use zuit_core::ComplexityMetrics;

/// Compute [`ComplexityMetrics`] for a single `syn` function body.
///
/// The visitor starts at nesting depth 0.  Only the block `stmts` / `expr`
/// are walked, not the function signature.
#[must_use]
pub(crate) fn compute(block: &syn::Block) -> ComplexityMetrics {
    let mut v = ComplexityVisitor::new();
    v.visit_block(block);
    ComplexityMetrics {
        cyclomatic: v.cyclomatic,
        cognitive: v.cognitive,
        max_nesting: v.max_nesting,
        returns: v.returns,
    }
}

// ── visitor ──────────────────────────────────────────────────────────────────

struct ComplexityVisitor {
    cyclomatic: u32,
    cognitive: u32,
    max_nesting: u32,
    returns: u32,
    /// Current control-flow nesting depth (0 = top-level of function body).
    depth: u32,
    /// Tracks the previous binary operator seen in the current expression
    /// position so we can implement the "chain" rule for `&&`/`||`.
    prev_bool_op: Option<BoolOp>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BoolOp {
    And,
    Or,
}

impl ComplexityVisitor {
    fn new() -> Self {
        Self {
            cyclomatic: 1, // baseline
            cognitive: 0,
            max_nesting: 0,
            returns: 0,
            depth: 0,
            prev_bool_op: None,
        }
    }

    /// Called when entering a nesting-eligible control-flow node.
    /// Adds `1 + depth` to cognitive and updates `max_nesting`.
    fn enter_nested(&mut self) {
        self.cognitive += 1 + self.depth;
        self.depth += 1;
        if self.depth > self.max_nesting {
            self.max_nesting = self.depth;
        }
    }

    /// Called when exiting a nesting-eligible control-flow node.
    fn exit_nested(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

impl<'ast> Visit<'ast> for ComplexityVisitor {
    // ── if ────────────────────────────────────────────────────────────────

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        // cyclomatic +1 per `if` (including `if let`)
        self.cyclomatic += 1;
        self.prev_bool_op = None;
        self.enter_nested();

        // Visit condition
        self.visit_expr(&node.cond);
        // Visit then-branch
        self.visit_block(&node.then_branch);

        self.exit_nested();

        // Visit else-branch (could be another ExprIf — handled recursively)
        if let Some((_, else_expr)) = &node.else_branch {
            self.visit_expr(else_expr);
        }
    }

    // ── while / while let ────────────────────────────────────────────────

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.cyclomatic += 1;
        self.prev_bool_op = None;
        self.enter_nested();
        syn::visit::visit_expr_while(self, node);
        self.exit_nested();
    }

    // ── for ──────────────────────────────────────────────────────────────

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.cyclomatic += 1;
        self.prev_bool_op = None;
        self.enter_nested();
        syn::visit::visit_expr_for_loop(self, node);
        self.exit_nested();
    }

    // ── loop ─────────────────────────────────────────────────────────────

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        // loop itself only adds nesting; conditional breaks inside add cyclomatic.
        self.prev_bool_op = None;
        self.enter_nested();
        syn::visit::visit_expr_loop(self, node);
        self.exit_nested();
    }

    // ── match ────────────────────────────────────────────────────────────

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        // cyclomatic: +1 per arm beyond the first (i.e., total arms - 1, min 0)
        // arm count fits in u32 since it's bounded by source file size.
        #[allow(clippy::cast_possible_truncation)]
        let arm_count = node.arms.len() as u32;
        self.cyclomatic += arm_count.saturating_sub(1);
        self.prev_bool_op = None;
        self.enter_nested();

        // Visit the scrutinee
        self.visit_expr(&node.expr);

        // Visit each arm (which may contain nested control flow)
        for arm in &node.arms {
            syn::visit::visit_arm(self, arm);
        }

        self.exit_nested();
    }

    // ── ? operator ───────────────────────────────────────────────────────

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.cyclomatic += 1;
        syn::visit::visit_expr_try(self, node);
    }

    // ── break with value (conditional break in loop) ─────────────────────

    fn visit_expr_break(&mut self, node: &'ast syn::ExprBreak) {
        if node.expr.is_some() {
            // conditional break — counts as a branch
            self.cyclomatic += 1;
        }
        syn::visit::visit_expr_break(self, node);
    }

    // ── return ───────────────────────────────────────────────────────────

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        self.returns += 1;
        syn::visit::visit_expr_return(self, node);
    }

    // ── && / || — Sonar chain rule ────────────────────────────────────────

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        use syn::BinOp;
        match node.op {
            BinOp::And(_) => {
                // cyclomatic: always +1 per operator
                self.cyclomatic += 1;
                // cognitive: +1 only if this starts a new chain (prev was not And)
                if self.prev_bool_op != Some(BoolOp::And) {
                    self.cognitive += 1;
                }
                let prev = self.prev_bool_op;
                self.prev_bool_op = Some(BoolOp::And);
                self.visit_expr(&node.left);
                self.prev_bool_op = Some(BoolOp::And);
                self.visit_expr(&node.right);
                self.prev_bool_op = prev;
            }
            BinOp::Or(_) => {
                self.cyclomatic += 1;
                if self.prev_bool_op != Some(BoolOp::Or) {
                    self.cognitive += 1;
                }
                let prev = self.prev_bool_op;
                self.prev_bool_op = Some(BoolOp::Or);
                self.visit_expr(&node.left);
                self.prev_bool_op = Some(BoolOp::Or);
                self.visit_expr(&node.right);
                self.prev_bool_op = prev;
            }
            _ => {
                self.prev_bool_op = None;
                syn::visit::visit_expr_binary(self, node);
            }
        }
    }

    // ── closures: push/pop nesting but do NOT reset cyclomatic baseline ───

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.enter_nested();
        syn::visit::visit_expr_closure(self, node);
        self.exit_nested();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a single function and return its body block.
    fn parse_fn(code: &str) -> syn::Block {
        let file: syn::File = syn::parse_str(code).expect("failed to parse");
        for item in file.items {
            if let syn::Item::Fn(f) = item {
                return *f.block;
            }
        }
        panic!("no function found in snippet");
    }

    fn metrics(code: &str) -> ComplexityMetrics {
        compute(&parse_fn(code))
    }

    #[test]
    fn empty_function_cyclomatic_1() {
        let m = metrics("fn f() {}");
        assert_eq!(m.cyclomatic, 1, "baseline is 1");
        assert_eq!(m.cognitive, 0);
        assert_eq!(m.max_nesting, 0);
        assert_eq!(m.returns, 0);
    }

    #[test]
    fn single_if_cyclomatic_2() {
        // if adds +1 → total 2; cognitive +1 (depth 0 → +1+0)
        let m = metrics("fn f(x: bool) { if x { let _ = 1; } }");
        assert_eq!(m.cyclomatic, 2);
        assert_eq!(m.cognitive, 1);
        assert_eq!(m.max_nesting, 1);
    }

    #[test]
    fn cyclomatic_3() {
        // two `if` expressions → 1 + 1 + 1 = 3
        let m = metrics(
            "fn f(a: bool, b: bool) {
                 if a { let _ = 1; }
                 if b { let _ = 2; }
             }",
        );
        assert_eq!(m.cyclomatic, 3);
    }

    #[test]
    fn cyclomatic_7_complex() {
        // if + while + for + match(3 arms→+2) + ? = 1+1+1+1+2+1 = 7
        let m = metrics(
            r"
            fn f(v: Vec<i32>) -> Option<i32> {
                if v.is_empty() { return None; }
                while let Some(x) = v.first() {
                    let _ = x;
                    break;
                }
                for _ in &v {}
                let r: Option<i32> = match v.len() {
                    0 => None,
                    1 => Some(1),
                    _ => Some(2),
                };
                Some(r?)
            }
            ",
        );
        assert_eq!(m.cyclomatic, 7);
    }

    #[test]
    fn question_mark_adds_cyclomatic() {
        let m = metrics(
            r"
            fn f() -> Result<(), ()> {
                let _ = Ok::<i32, ()>(1)?;
                Ok(())
            }
            ",
        );
        assert_eq!(m.cyclomatic, 2); // 1 baseline + 1 for ?
    }

    #[test]
    fn and_or_cyclomatic() {
        let m = metrics("fn f(a: bool, b: bool, c: bool) -> bool { a && b || c }");
        // && adds +1, || adds +1 → 1 + 2 = 3
        assert_eq!(m.cyclomatic, 3);
    }

    #[test]
    fn return_count() {
        let m = metrics("fn f(x: i32) -> i32 { if x > 0 { return x; } return 0; }");
        assert_eq!(m.returns, 2);
    }

    #[test]
    fn match_two_arms_adds_one() {
        let m = metrics("fn f(x: i32) -> i32 { match x { 0 => 1, _ => 2 } }");
        // match: arms beyond first = 2-1 = 1 → cyclomatic = 1 + 1 = 2
        assert_eq!(m.cyclomatic, 2);
    }

    #[test]
    fn cognitive_nesting_bonus() {
        // Nested if: outer adds (1+0)=1, inner adds (1+1)=2 → cognitive = 3
        let m = metrics(
            "fn f(a: bool, b: bool) {
                 if a {
                     if b {
                         let _ = 1;
                     }
                 }
             }",
        );
        assert_eq!(m.cognitive, 3); // outer 1 + inner (1+1)
        assert_eq!(m.max_nesting, 2);
    }

    #[test]
    fn and_chain_cognitive_counts_once() {
        // a && b && c: one chain of &&, should add +1 cognitive (not +2)
        let m = metrics("fn f(a: bool, b: bool, c: bool) -> bool { a && b && c }");
        // cyclomatic: 1 + 2 = 3; cognitive: 1 (one && chain)
        assert_eq!(m.cyclomatic, 3);
        assert_eq!(m.cognitive, 1);
    }
}
