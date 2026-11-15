//! A JSON reader for the test data of `tests/hpack-test-case`: objects, arrays, strings, integers,
//! and `null`. It panics on input that is not JSON, because the data is fixed.

/// One JSON value. A string is its bytes in UTF-8. An object keeps the order of its members.
#[derive(Debug)]
pub(crate) enum Json {
    Null,
    Number(u64),
    String(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
}

impl Json {
    /// Reads the one value of `text`.
    pub(crate) fn parse(text: &[u8]) -> Self {
        let mut reader = Reader { text, at: 0 };
        let value = reader.value();
        reader.space();
        assert_eq!(reader.at, text.len(), "bytes after the JSON value");
        value
    }

    /// The member `key` of an object.
    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        let Self::Object(members) = self else { return None };
        members
            .iter()
            .find(|(name, _)| name == key.as_bytes())
            .map(|(_, value)| value)
    }
}

struct Reader<'a> {
    text: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn space(&mut self) {
        while self.text.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }

    fn next(&mut self) -> u8 {
        let byte = self.text[self.at];
        self.at += 1;
        byte
    }

    fn expect(&mut self, bytes: &[u8]) {
        assert_eq!(&self.text[self.at..self.at + bytes.len()], bytes, "at byte {}", self.at);
        self.at += bytes.len();
    }

    fn value(&mut self) -> Json {
        self.space();
        match self.text[self.at] {
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                self.list(b'}', |reader| {
                    reader.space();
                    let name = reader.string();
                    reader.space();
                    reader.expect(b":");
                    members.push((name, reader.value()));
                });
                Json::Object(members)
            }
            b'[' => {
                self.at += 1;
                let mut values = Vec::new();
                self.list(b']', |reader| values.push(reader.value()));
                Json::Array(values)
            }
            b'"' => Json::String(self.string()),
            b'n' => {
                self.expect(b"null");
                Json::Null
            }
            _ => {
                let start = self.at;
                while self.text.get(self.at).is_some_and(u8::is_ascii_digit) {
                    self.at += 1;
                }
                let digits = core::str::from_utf8(&self.text[start..self.at]).expect("ASCII digits");
                Json::Number(digits.parse().expect("an integer"))
            }
        }
    }

    /// Reads the items of an array or an object until `end`, with `item` for each.
    fn list(&mut self, end: u8, mut item: impl FnMut(&mut Self)) {
        self.space();
        if self.text[self.at] == end {
            self.at += 1;
            return;
        }
        loop {
            item(self);
            self.space();
            match self.next() {
                b',' => {}
                byte => {
                    assert_eq!(byte, end, "at byte {}", self.at);
                    return;
                }
            }
        }
    }

    fn string(&mut self) -> Vec<u8> {
        self.expect(b"\"");
        let mut bytes = Vec::new();
        loop {
            match self.next() {
                b'"' => return bytes,
                b'\\' => match self.next() {
                    b'u' => {
                        let hex = core::str::from_utf8(&self.text[self.at..self.at + 4]).expect("hex digits");
                        self.at += 4;
                        let code = u32::from_str_radix(hex, 16).expect("hex digits");
                        let char = char::from_u32(code).expect("a scalar value, with no surrogate");
                        bytes.extend_from_slice(char.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                    escape => bytes.push(match escape {
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        other => other,
                    }),
                },
                byte => bytes.push(byte),
            }
        }
    }
}
