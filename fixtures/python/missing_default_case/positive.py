# MAINT009-missing-default-case — positive fixture
# This match statement should produce a finding.

def check_status(status):
    match status:
        case 1:
            print("one")
        case 2:
            print("two")
