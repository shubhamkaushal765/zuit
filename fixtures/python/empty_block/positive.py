# Fixture: positive cases for MAINT013-empty-block (Python)
# Each of the following should produce a finding.

x = 1

# Empty if body
if x:
    pass

# Empty for body
for i in range(10):
    pass

# Empty while body
while False:
    pass
