// SEC012-hardcoded-security-constant: negative fixture
// None of the following should produce findings.

// RHS is a member expression (environment variable lookup)
const api_key = process.env.API_KEY;
const password = process.env.PASSWORD;

// Excluded suffixes
const total_password_count = 0;
const secret_handler = new Object();
const token_type = "bearer";

// Empty string
const passwordHash = "";

// Unrelated names
const username = "admin";
const host = "localhost";
