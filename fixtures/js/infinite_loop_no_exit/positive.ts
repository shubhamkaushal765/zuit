// MAINT010-infinite-loop-no-exit: positive fixture
// These loops should be flagged.

function spin(): void {
    let x = 0;
    while (true) {
        x++;
    }
}

function foreverFor(): void {
    let y = 0;
    for (;;) {
        y++;
    }
}
