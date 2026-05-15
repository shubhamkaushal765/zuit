//! Cyclomatic and cognitive complexity counters for JavaScript / TypeScript
//! function bodies.
//!
//! # Cyclomatic complexity rules
//!
//! Baseline 1; +1 for each branching construct in the function body:
//!
//! - `if` (each `else if` reads as a nested `if` and adds 1).
//! - `while`, `do-while`, `for`, `for-in`, `for-of`.
//! - Each `case` clause in a `switch` (counted from the `cases` list).
//! - `catch` clause.
//! - Ternary `cond ? a : b`.
//! - Each `&&`, `||`, or `??` operator occurrence.
//!
//! # Cognitive complexity rules (Sonar variant)
//!
//! Structural increments (`depth + 1`):
//! - `if`, `while`, `do-while`, `for`, `for-in`, `for-of`.
//! - `switch` (the construct, not each case).
//! - `try` block, each `catch` clause.
//! - Each nested function or class declaration.
//!
//! Flat increments (`+1`, regardless of depth):
//! - Each `&&`, `||`, `??` operator occurrence.
//! - `break`/`continue` (only when targeted with a label).
//! - `lambda`-style arrow expressions inside an expression position.
//!
//! Nesting depth increases when entering: `if` body, `while`/`for` body,
//! `switch`, `try`, `catch`, nested function body.

use oxc_ast::ast::{Expression, Statement};

use zuit_core::ComplexityMetrics;

/// Computes [`ComplexityMetrics`] for a sequence of statements (a function or
/// arrow-function body).
pub(crate) fn compute_function_complexity(body: &[Statement<'_>]) -> ComplexityMetrics {
    let mut counter = ComplexityCounter::new();
    counter.cyclomatic = 1;
    counter.walk_stmts(body, 0);
    ComplexityMetrics {
        cyclomatic: counter.cyclomatic,
        cognitive: counter.cognitive,
        max_nesting: counter.max_nesting,
        returns: counter.returns,
    }
}

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

    // ── statement walker ────────────────────────────────────────────────────

    fn walk_stmts(&mut self, stmts: &[Statement<'_>], depth: u32) {
        for stmt in stmts {
            self.walk_stmt(stmt, depth);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn walk_stmt(&mut self, stmt: &Statement<'_>, depth: u32) {
        self.update_max_nesting(depth);
        match stmt {
            Statement::IfStatement(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_expr(&s.test, depth);
                self.walk_stmt(&s.consequent, depth + 1);
                if let Some(alt) = &s.alternate {
                    // `else if (...)` arrives here as another `IfStatement`,
                    // so it gets its own +1 cyclomatic / structural-cognitive
                    // automatically.
                    self.walk_stmt(alt, depth);
                }
            }
            Statement::WhileStatement(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_expr(&s.test, depth);
                self.walk_stmt(&s.body, depth + 1);
            }
            Statement::DoWhileStatement(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_stmt(&s.body, depth + 1);
                self.walk_expr(&s.test, depth);
            }
            Statement::ForStatement(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                if let Some(t) = &s.test {
                    self.walk_expr(t, depth);
                }
                self.walk_stmt(&s.body, depth + 1);
            }
            Statement::ForInStatement(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_expr(&s.right, depth);
                self.walk_stmt(&s.body, depth + 1);
            }
            Statement::ForOfStatement(s) => {
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_expr(&s.right, depth);
                self.walk_stmt(&s.body, depth + 1);
            }
            Statement::SwitchStatement(s) => {
                // +1 cyclomatic per case clause (matches gcov/eslint
                // complexity counting).
                let case_count = u32::try_from(s.cases.len()).unwrap_or(u32::MAX);
                self.cyclomatic = self.cyclomatic.saturating_add(case_count);
                self.cognitive += depth + 1;
                self.walk_expr(&s.discriminant, depth);
                for case in &s.cases {
                    if let Some(test) = &case.test {
                        self.walk_expr(test, depth + 1);
                    }
                    self.walk_stmts(&case.consequent, depth + 1);
                }
            }
            Statement::TryStatement(s) => {
                self.cognitive += depth + 1;
                self.walk_stmts(&s.block.body, depth + 1);
                if let Some(h) = &s.handler {
                    // `catch` block: +1 cyclomatic, structural cognitive.
                    self.cyclomatic += 1;
                    self.cognitive += depth + 1;
                    self.walk_stmts(&h.body.body, depth + 1);
                }
                if let Some(f) = &s.finalizer {
                    self.walk_stmts(&f.body, depth + 1);
                }
            }
            Statement::ReturnStatement(s) => {
                self.returns += 1;
                if let Some(arg) = &s.argument {
                    self.walk_expr(arg, depth);
                }
            }
            Statement::BreakStatement(s) if s.label.is_some() => {
                self.cognitive += 1;
            }
            Statement::ContinueStatement(s) if s.label.is_some() => {
                self.cognitive += 1;
            }
            Statement::BlockStatement(b) => {
                self.walk_stmts(&b.body, depth);
            }
            Statement::LabeledStatement(s) => self.walk_stmt(&s.body, depth),
            Statement::ExpressionStatement(es) => self.walk_expr(&es.expression, depth),
            Statement::ThrowStatement(s) => self.walk_expr(&s.argument, depth),
            Statement::FunctionDeclaration(f) => {
                // Nested function: structural cognitive, walk its body at +1.
                self.cognitive += depth + 1;
                if let Some(body) = &f.body {
                    self.walk_stmts(&body.statements, depth + 1);
                }
            }
            Statement::ClassDeclaration(c) => {
                // Walk methods so nested logic still counts toward this
                // function's cognitive complexity (matches Python frontend's
                // treatment of class definitions inside functions).
                self.cognitive += depth + 1;
                for elt in &c.body.body {
                    if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                        && let Some(body) = &m.value.body
                    {
                        self.walk_stmts(&body.statements, depth + 1);
                    }
                }
            }
            Statement::VariableDeclaration(v) => {
                for d in &v.declarations {
                    if let Some(init) = &d.init {
                        self.walk_expr(init, depth);
                    }
                }
            }
            // Other statement variants (debugger, empty, with, …) carry no
            // complexity-relevant content.
            _ => {}
        }
    }

    // ── expression walker ───────────────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    fn walk_expr(&mut self, expr: &Expression<'_>, depth: u32) {
        // Several variants share the empty-body fall-through with `_`;
        // listing them explicitly would just trip clippy's identical-arms lint.
        match expr {
            Expression::LogicalExpression(l) => {
                // `&&`, `||`, `??` — flat +1 cognitive, +1 cyclomatic.
                self.cyclomatic += 1;
                self.cognitive += 1;
                self.walk_expr(&l.left, depth);
                self.walk_expr(&l.right, depth);
            }
            Expression::ConditionalExpression(c) => {
                // Ternary `a ? b : c`.
                self.cyclomatic += 1;
                self.cognitive += depth + 1;
                self.walk_expr(&c.test, depth);
                self.walk_expr(&c.consequent, depth + 1);
                self.walk_expr(&c.alternate, depth + 1);
            }
            Expression::BinaryExpression(b) => {
                self.walk_expr(&b.left, depth);
                self.walk_expr(&b.right, depth);
            }
            Expression::UnaryExpression(u) => self.walk_expr(&u.argument, depth),
            Expression::CallExpression(c) => {
                self.walk_expr(&c.callee, depth);
                for arg in &c.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.walk_expr(e, depth);
                    }
                }
            }
            Expression::NewExpression(c) => {
                self.walk_expr(&c.callee, depth);
                for arg in &c.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.walk_expr(e, depth);
                    }
                }
            }
            Expression::ArrayExpression(a) => {
                for elt in &a.elements {
                    if let Some(e) = elt.as_expression() {
                        self.walk_expr(e, depth);
                    }
                }
            }
            Expression::ObjectExpression(o) => {
                for prop in &o.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                        self.walk_expr(&p.value, depth);
                    }
                }
            }
            Expression::AssignmentExpression(a) => self.walk_expr(&a.right, depth),
            Expression::SequenceExpression(s) => {
                for e in &s.expressions {
                    self.walk_expr(e, depth);
                }
            }
            Expression::AwaitExpression(a) => self.walk_expr(&a.argument, depth),
            Expression::YieldExpression(y) => {
                if let Some(arg) = &y.argument {
                    self.walk_expr(arg, depth);
                }
            }
            Expression::ParenthesizedExpression(p) => self.walk_expr(&p.expression, depth),
            Expression::ArrowFunctionExpression(a) => {
                // Arrow inside an expression — flat +1 cognitive (a "lambda"
                // for Sonar's purposes); we still walk into the body so any
                // nested control flow counts toward THIS function (an arrow
                // body is logically a closure but cognitive-complexity-wise
                // analyzers usually treat it inline).
                self.cognitive += 1;
                self.walk_stmts(&a.body.statements, depth + 1);
            }
            Expression::FunctionExpression(f) => {
                self.cognitive += depth + 1;
                if let Some(body) = &f.body {
                    self.walk_stmts(&body.statements, depth + 1);
                }
            }
            Expression::TemplateLiteral(t) => {
                for e in &t.expressions {
                    self.walk_expr(e, depth);
                }
            }
            Expression::TSAsExpression(e) => self.walk_expr(&e.expression, depth),
            Expression::TSSatisfiesExpression(e) => self.walk_expr(&e.expression, depth),
            Expression::TSNonNullExpression(e) => self.walk_expr(&e.expression, depth),
            Expression::TSTypeAssertion(e) => self.walk_expr(&e.expression, depth),
            // Literals, identifiers, member-access, this, super — no flow.
            _ => {}
        }
    }
}
