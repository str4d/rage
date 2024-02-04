# How to contribute to `rage`

## Localization

Locale files are stored in the `age/i18n/` and `rage/i18n/` directories. Check
there to see if your locale already exists!

We use [Fluent](https://projectfluent.org/) for localization; check that website
for details about the format. In general, strings look like this:

```fluent
some-unique-identifier = Translate the content on this side of the '=' symbol.
another-unique-identifier =
    This is a multiline string that can contain one or more paragraphs. Like
    above, the 'another-unique-identifier =' part is not translated, but this
    text is.

    Individual paragraphs should be line-wrapped at roughly the same number of
    characters as the corresponding English text, so that it looks roughly the
    same. Remember that {-terms} and {$variables} won't necessarily be the same
    length once filled in.
```

To update strings for an existing locale `your-locale`:
- Compare `age/i18n/en-US/age.ftl` with `age/i18n/your-locale/age.ftl`, and copy
  over any missing strings (look for unique identifiers that don't appear in the
  file for `your-locale`).
- Compare `rage/i18n/en-US/age.ftl` with `rage/i18n/your-locale/age.ftl`, and
  copy over any missing strings.
- Edit `age/i18n/your-locale/age.ftl` and `rage/i18n/your-locale/age.ftl` to
  replace the English text with the appropriate translations for your locale.

To translate strings into a new locale `your-locale`:
- Create the directories `age/i18n/your-locale/` and `rage/i18n/your-locale/`.
- Copy `age/i18n/en-US/age.ftl` to `age/i18n/your-locale/age.ftl`.
- Copy `rage/i18n/en-US/age.ftl` to `rage/i18n/your-locale/age.ftl`.
- Edit `age/i18n/your-locale/age.ftl` and `rage/i18n/your-locale/age.ftl` to
  replace the English text with the appropriate translations for your locale.

To test locally, use `cargo run --bin BINARY_NAME -- ARGUMENTS`. If you don't
have `your-locale` enabled globally, set the `LANG` environment variable to
force it:
```
$ LANG=your-locale cargo run --bin rage -- --help
$ LANG=your-locale cargo run --bin rage -- ARGUMENTS
$ LANG=your-locale cargo run --bin rage-keygen -- --help
```
