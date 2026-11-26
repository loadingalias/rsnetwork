//! The priority of RFC 9218 (N212): the parser of Structured Field Dictionaries against the
//! official suite of RFC 9651 in `tests/structured-field-tests`, and the parameters `u` and `i`.

mod json;

use std::fs;
use std::path::Path;

use json::Json;
use rsnetwork::priority::{Priority, Urgency};

/// Applies the member `key` with the expected `value` of the suite: an item, `[bare, parameters]`,
/// or an inner list, `[[items], parameters]`. `u` takes an integer in 0 to 7, and `i` a boolean;
/// another value keeps the default (RFC 9218, section 4).
fn apply(priority: &mut Priority, key: &[u8], value: &[Json]) {
    match (key, value.first()) {
        (b"u", Some(Json::Integer(urgency @ 0..=7))) => {
            priority.urgency = Urgency::new(u8::try_from(*urgency).unwrap()).unwrap();
        }
        (b"u", _) => priority.urgency = Urgency::DEFAULT,
        (b"i", Some(Json::Bool(incremental))) => priority.incremental = *incremental,
        (b"i", _) => priority.incremental = false,
        _ => {}
    }
}

/// The priority of the expected members of a dictionary of the suite, each `[key, value]`.
fn expected(members: &[Json]) -> Priority {
    let mut priority = Priority::DEFAULT;
    for member in members {
        let Json::Array(pair) = member else {
            panic!("a member is a pair")
        };
        let [Json::String(key), Json::Array(value)] = &pair[..] else {
            panic!("a member is a key and a value")
        };
        apply(&mut priority, key, value);
    }
    priority
}

/// `bytes` with no SP at its start or end, which the parse of a field value discards.
fn trim_sp(mut bytes: &[u8]) -> &[u8] {
    while let [b' ', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' '] = bytes {
        bytes = rest;
    }
    bytes
}

/// Checks the parse of `value` against a record of the suite: refused when it must fail, and the
/// expected priority when it must parse. A record that can fail can give either.
fn check(name: &str, value: &[u8], record: &Json, expect: impl FnOnce() -> Priority) {
    let flag = |key| matches!(record.get(key), Some(Json::Bool(true)));
    let parsed = Priority::parse(value);
    if flag("must_fail") {
        assert_eq!(parsed, None, "{name}: {:?}", String::from_utf8_lossy(value));
    } else if let Some(parsed) = parsed {
        assert_eq!(parsed, expect(), "{name}: {:?}", String::from_utf8_lossy(value));
    } else {
        assert!(
            flag("can_fail"),
            "{name}: {:?} must parse",
            String::from_utf8_lossy(value)
        );
    }
}

#[test]
fn each_dictionary_and_item_of_the_structured_field_suite_parses_as_the_suite_says() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/structured-field-tests");
    let (mut dictionaries, mut items) = (0, 0);
    let mut files: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    for file in files
        .iter()
        .filter(|file| file.extension().is_some_and(|extension| extension == "json"))
    {
        let Json::Array(records) = Json::parse(&fs::read(file).unwrap()) else {
            panic!("{file:?} holds an array")
        };
        for record in &records {
            let Some(Json::String(name)) = record.get("name") else {
                panic!("a record has a name")
            };
            let name = format!("{}: {}", file.display(), String::from_utf8_lossy(name));
            let Some(Json::Array(raw)) = record.get("raw") else {
                panic!("{name}: a record has lines")
            };
            let lines: Vec<&[u8]> = raw
                .iter()
                .map(|line| match line {
                    Json::String(line) => &line[..],
                    _ => panic!("{name}: a line is a string"),
                })
                .collect();
            let members = || match record.get("expected") {
                Some(Json::Array(members)) => &members[..],
                _ => panic!("{name}: a record that parses has its value"),
            };
            match record.get("header_type") {
                Some(Json::String(kind)) if kind == b"dictionary" => {
                    // A field of several lines is one value, with a comma between its lines.
                    check(&name, &lines.join(&b", "[..]), record, || expected(members()));
                    dictionaries += 1;
                }
                Some(Json::String(kind)) if kind == b"item" && lines.len() == 1 => {
                    // An item is the value of a member, with no SP at its ends. A member value
                    // can also be an inner list, a tab can follow a member, and a comma can start
                    // the next member of a value that is not an item, so those records differ.
                    let item = trim_sp(lines[0]);
                    let must_fail = matches!(record.get("must_fail"), Some(Json::Bool(true)));
                    if item.starts_with(b"(") || item.ends_with(b"\t") || (must_fail && item.contains(&b',')) {
                        continue;
                    }
                    for key in [&b"u"[..], b"i"] {
                        let value = [key, b"=", item].concat();
                        let member = || {
                            let mut priority = Priority::DEFAULT;
                            apply(&mut priority, key, members());
                            priority
                        };
                        check(&name, &value, record, member);
                    }
                    items += 1;
                }
                _ => {}
            }
        }
    }
    // Each record of the subset, so a change of the data or of the filter shows.
    assert_eq!((dictionaries, items), (431, 840));
}

#[test]
fn the_field_of_each_priority_reads_back_as_that_priority() {
    for urgency in 0..=7 {
        for incremental in [false, true] {
            let priority = Priority {
                urgency: Urgency::new(urgency).unwrap(),
                incremental,
            };
            let field = priority.field();
            assert_eq!(field.name(), b"priority");
            assert_eq!(Priority::parse(field.value()), Some(priority), "{priority:?}");
        }
    }
}

#[test]
fn the_last_member_of_a_parameter_wins_also_when_the_receiver_ignores_its_value() {
    let urgent = |urgency| Priority {
        urgency: Urgency::new(urgency).unwrap(),
        incremental: false,
    };
    assert_eq!(Priority::parse(b"u=1, u=2"), Some(urgent(2)));
    // The last value is out of range: the parameter keeps its default, not the first value.
    assert_eq!(Priority::parse(b"u=1, u=8"), Some(Priority::DEFAULT));
    assert_eq!(Priority::parse(b"u=1, u=\"1\""), Some(Priority::DEFAULT));
    assert_eq!(Priority::parse(b"i, i=?0"), Some(Priority::DEFAULT));
    assert_eq!(Priority::parse(b"i=1"), Some(Priority::DEFAULT));
    assert_eq!(
        Priority::parse(b"u=0;x=1, i;y"),
        Some(Priority {
            incremental: true,
            ..urgent(0)
        })
    );
}
