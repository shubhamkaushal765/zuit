// Fixture: negative cases for MAINT013-empty-block (JS/TS)
// None of the following should produce a finding.

const x = 1;

// Non-empty if
if (x) {
    console.log(x);
}

// Non-empty while
let count = 0;
while (count < 10) {
    count++;
}

// Non-empty for
for (let i = 0; i < 10; i++) {
    console.log(i);
}

// Intentional catch swallow with `_`
function safeCall() {
    try {
        doSomething();
    } catch (_) {}
}

declare function doSomething(): void;
