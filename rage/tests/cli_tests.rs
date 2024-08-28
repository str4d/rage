#[test]
fn cli_tests() {
    let tests = trycmd::TestCases::new();

    tests.case("tests/cmd/*/*.toml");

    #[cfg(unix)]
    tests.case("tests/unix/*/*.toml");

    #[cfg(not(unix))]
    tests.case("tests/windows/*/*.toml");
}
