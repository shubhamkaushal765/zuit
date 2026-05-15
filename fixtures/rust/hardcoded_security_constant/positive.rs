// SEC012-hardcoded-security-constant: positive fixture
// All of the following should produce findings.

static API_KEY: &str = "test";
const MY_SECRET: &str = "hardcoded";

fn configure() {
    let password = "admin";
    let _ = password;

    let private_key = "abc";
    let _ = private_key;
}
