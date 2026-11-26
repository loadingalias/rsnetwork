# structured-field-tests

This directory is test data from <https://github.com/httpwg/structured-field-tests>, at commit
`4a4782f8234512af133f6f57c4ca998578b57110` (2026-11-17), under the license in `LICENSE.md`. The
files are not changed. They test parsers of Structured Fields, RFC 9651.

Subset rule: each parsing file of the suite, except `list.json`, `listlist.json`,
`param-list.json`, `param-listlist.json`, and `large-generated.json`. The `serialisation-tests`
directory, `schema`, and `generate.py` are not here either. `tests/priority.rs` parses each
dictionary record, and each item record with one field line as the value of a dictionary member.
It skips the list records that the other files hold.
