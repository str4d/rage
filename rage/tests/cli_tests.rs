#[test]
fn cli_tests() {
    let tests = trycmd::TestCases::new();

    tests.case("tests/cmd/*/*.toml");

    #[cfg(unix)]
    tests.case("tests/unix/*/*.toml");

    // `i18n-embed 0.16.0` switched to `sys-locale` for resolving locales, which does not
    // implement environment variable overrides on Windows, Apple, or Android (instead
    // just using OS APIs).
    #[cfg(all(unix, not(any(target_vendor = "apple", target_os = "android"))))]
    tests.case("tests/unix_not_apple_android/*/*.toml");

    #[cfg(not(unix))]
    tests.case("tests/windows/*/*.toml");
}
