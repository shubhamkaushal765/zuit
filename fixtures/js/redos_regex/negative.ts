// Negative fixture for SEC014-redos-regex — safe regex patterns.

// Simple character class — no nesting.
const r1 = /[a-z]+/;

// Bounded repetition.
const r2 = /\d{1,5}/;

// Anchored literal.
const r3 = /^abc$/;

// new RegExp with safe pattern.
const r4 = new RegExp("[a-z]+");
