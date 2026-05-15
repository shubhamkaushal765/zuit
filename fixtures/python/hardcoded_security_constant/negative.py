# SEC012-hardcoded-security-constant: negative fixture
# None of the following should produce findings.

import os

# RHS is a call expression (environment variable lookup)
password = os.environ["PASSWORD"]
api_key = os.getenv("API_KEY")

# Excluded suffixes
total_password_count = 0
secret_handler = None
token_type = "bearer"
auth_name = "admin"

# Empty string
password_hash = ""

# Unrelated names
username = "admin"
host = "localhost"
