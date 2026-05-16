# MAINT010-infinite-loop-no-exit: positive fixture
# These loops should be flagged.

def spin():
    x = 0
    while True:
        x += 1
