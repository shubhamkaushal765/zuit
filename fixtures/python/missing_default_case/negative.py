# MAINT009-missing-default-case — negative fixture
# These match statements should NOT produce findings.

def check_with_underscore(x):
    match x:
        case 1:
            print("one")
        case _:
            print("other")


def check_with_capture(x):
    match x:
        case 1:
            print("one")
        case other:
            print(f"other: {other}")
