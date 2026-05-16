// MAINT010-infinite-loop-no-exit: negative fixture
// These loops should NOT be flagged.

function loopWithBreak(x: boolean): void {
    while (true) {
        if (x) break;
    }
}

function loopWithReturn(): void {
    while (true) {
        return;
    }
}

function forWithThrow(): void {
    for (;;) {
        throw new Error("unexpected");
    }
}
