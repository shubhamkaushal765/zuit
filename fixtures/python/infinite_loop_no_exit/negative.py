# MAINT010-infinite-loop-no-exit: negative fixture
# These loops should NOT be flagged.

def loop_with_break(x):
    while True:
        if x:
            break

def loop_with_return():
    while True:
        return None

def loop_not_true(x):
    while x > 0:
        x -= 1
