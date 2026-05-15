# Fixture: MAINT011-active-debug-code — Python positive cases
# Each call below should produce a finding.

def process_data(data):
    print(data)          # should be flagged
    return data


def debug_session():
    breakpoint()         # should be flagged


def inspect_value(obj):
    import pdb
    pdb.set_trace()      # should be flagged
