// SEC002-eval-sink positive fixture (JavaScript)
// Every expression here should trigger at least one finding.

// 1. bare eval call
const userInput = "1 + 1";
const result = eval(userInput);

// 2. new Function constructor
const fn1 = new Function("return 1");

// 3. bare Function() call (used as constructor without `new`)
const fn2 = Function("return 2");

// 4. setTimeout with string literal
setTimeout("alert(1)", 1000);

// 5. setInterval with string literal
setInterval("doThing()", 500);

// 6. setTimeout with template literal (no substitutions)
setTimeout(`alert(1)`, 0);
