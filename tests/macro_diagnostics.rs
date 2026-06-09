#[test]
fn roles_allowed_macro_diagnostics() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/roles_allowed_*.rs");
}
