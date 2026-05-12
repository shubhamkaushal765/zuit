// SEC002-eval-sink negative fixture (JavaScript)
// None of these should trigger a finding.

// setTimeout/setInterval with function arguments — safe
setTimeout(() => console.log("hi"), 100);
setInterval(function () { doThing(); }, 500);

// Member-access eval — out of scope for v1
const obj = { eval: (x) => x };
obj.eval("not flagged");

// console.log containing the string "eval" — not a call to eval
console.log("eval");

// arr.map(eval) — passing eval as a reference, not calling it as a bare name
// (debatable; we document the choice: bare-call detection only, no reference tracking)
const arr = [1, 2, 3];

// Safe dynamic scheduling with function reference
function handler() {}
setTimeout(handler, 200);

// String variable, but not passed as first arg to setTimeout
const code = "doThing()";
console.log(code);
