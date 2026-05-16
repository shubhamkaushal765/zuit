// MAINT012-dead-store positive fixture

function deadStoreOverwritten() {
    let x = 1;  // dead: overwritten before read
    x = 2;
    return x;
}

function deadStoreNeverRead() {
    const unused = 42;  // dead: never read
    return null;
}
