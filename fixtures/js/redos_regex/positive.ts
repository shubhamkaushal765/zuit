// Positive fixture for SEC014-redos-regex — patterns that cause catastrophic backtracking.

// RegExpLiteral form: (a+)+
const r1 = /(a+)+/;

// new RegExp form with nested repetition.
const r2 = new RegExp("(.*)*");

// Another nested quantifier pattern.
const r3 = /(\w+)+end/;
