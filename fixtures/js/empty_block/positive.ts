// Fixture: positive cases for MAINT013-empty-block (JS/TS)
// Each of the following should produce a finding.

const x = 1;

// Empty if body
if (x) {}

// Empty while body
while (false) {}

// Empty for body
for (let i = 0; i < 10; i++) {}

// Empty catch with named param (not intentional swallow)
function test() {
    try {
        doSomething();
    } catch (e) {}
}

declare function doSomething(): void;
