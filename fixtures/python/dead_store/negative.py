# MAINT012-dead-store negative fixture
# None of the writes below should be flagged.


def read_after_write():
    x = 1
    return x   # x is read — not dead


def underscore_prefix():
    _x = 1
    return None   # _x skipped — leading underscore


def loop_variable():
    for x in range(10):
        pass   # loop var — skipped


def try_except_stores():
    x = 1
    try:
        x = 2
    except Exception:
        x = 3
    return x   # all writes inside try/except — skipped


def augmented_assignment():
    x = 0
    x += 1   # augmented — is also a load
    return x
