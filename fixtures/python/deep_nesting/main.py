"""Deep nesting fixture for MAINT005."""


def deeply_nested(x):
    if x > 0:
        if x > 10:
            if x > 100:
                if x > 1000:
                    if x > 10000:
                        return x * 2
    return x
