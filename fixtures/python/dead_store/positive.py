# MAINT012-dead-store positive fixture
# Each function below contains at least one dead store.


def dead_store_overwritten():
    x = 1      # dead: overwritten before any read
    x = 2
    return x


def dead_store_never_read():
    unused = 42   # dead: never read
    return None


def dead_store_multiple():
    result = compute()  # noqa: F821
    result = compute2()  # noqa: F821
    return result


def compute():
    return 0


def compute2():
    return 1
