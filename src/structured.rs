//! A parser of Structured Field Dictionaries (RFC 9651, sections 3.2 and 4.2.2).
//!
//! It checks each byte of a field value against the grammar of the dictionary, its items, inner
//! lists, and parameters, and it gives each member with its value. A field value that does not
//! parse is not a dictionary, and its receiver ignores the whole field (section 4.2). The parser
//! allocates nothing, and its work is linear in the bytes of the value.

/// The value of a dictionary member, as far as the fields of this crate read it. The parser checks
/// the parameters of an item, and does not give them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Integer(i64),
    Boolean(bool),
    /// Another item (a decimal, a string, a token, a byte sequence, a date, or a display string),
    /// or an inner list.
    Other,
}

/// A field value that is not a dictionary of RFC 9651.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Parses `input` as a dictionary, and gives `member` each member in its order, with its key. A
/// key can come more than one time: its last value is the value of the member (section 4.2.2).
/// After `Malformed`, discard each member that `member` got.
pub(crate) fn dictionary(input: &[u8], mut member: impl FnMut(&[u8], Value)) -> Result<(), Malformed> {
    let mut parser = Parser { input, at: 0 };
    parser.skip_sp();
    while parser.peek().is_some() {
        let key = parser.key()?;
        let value = if parser.eat(b'=') {
            parser.item_or_inner_list()?
        } else {
            parser.parameters()?;
            Value::Boolean(true)
        };
        member(key, value);
        parser.skip_ows();
        if parser.peek().is_none() {
            return Ok(());
        }
        if !parser.eat(b',') {
            return Err(Malformed);
        }
        parser.skip_ows();
        if parser.peek().is_none() {
            // A trailing comma.
            return Err(Malformed);
        }
    }
    Ok(())
}

/// A number: an integer, or a decimal, whose value no field of this crate reads.
#[derive(Clone, Copy)]
enum Number {
    Integer(i64),
    Decimal,
}

struct Parser<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn next(&mut self) -> Result<u8, Malformed> {
        let byte = self.peek().ok_or(Malformed)?;
        self.at += 1;
        Ok(byte)
    }

    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        self.at += usize::from(found);
        found
    }

    fn skip_sp(&mut self) {
        while self.eat(b' ') {}
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    /// Section 4.2.3.3.
    fn key(&mut self) -> Result<&'a [u8], Malformed> {
        let start = self.at;
        if !matches!(self.peek(), Some(b'a'..=b'z' | b'*')) {
            return Err(Malformed);
        }
        while matches!(self.peek(), Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')) {
            self.at += 1;
        }
        Ok(&self.input[start..self.at])
    }

    /// Section 4.2.1.1.
    fn item_or_inner_list(&mut self) -> Result<Value, Malformed> {
        if self.peek() != Some(b'(') {
            return self.item();
        }
        // Section 4.2.1.2.
        self.at += 1;
        loop {
            self.skip_sp();
            if self.eat(b')') {
                self.parameters()?;
                return Ok(Value::Other);
            }
            self.item()?;
            if !matches!(self.peek(), Some(b' ' | b')')) {
                return Err(Malformed);
            }
        }
    }

    /// Section 4.2.3.
    fn item(&mut self) -> Result<Value, Malformed> {
        let value = self.bare()?;
        self.parameters()?;
        Ok(value)
    }

    /// Section 4.2.3.2.
    fn parameters(&mut self) -> Result<(), Malformed> {
        while self.eat(b';') {
            self.skip_sp();
            self.key()?;
            if self.eat(b'=') {
                self.bare()?;
            }
        }
        Ok(())
    }

    /// Section 4.2.3.1.
    fn bare(&mut self) -> Result<Value, Malformed> {
        match self.peek().ok_or(Malformed)? {
            b'-' | b'0'..=b'9' => Ok(match self.number()? {
                Number::Integer(value) => Value::Integer(value),
                Number::Decimal => Value::Other,
            }),
            b'"' => {
                self.at += 1;
                self.string()?;
                Ok(Value::Other)
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'*' => {
                self.token();
                Ok(Value::Other)
            }
            b':' => {
                self.at += 1;
                self.bytes()?;
                Ok(Value::Other)
            }
            b'?' => {
                self.at += 1;
                match self.next()? {
                    b'1' => Ok(Value::Boolean(true)),
                    b'0' => Ok(Value::Boolean(false)),
                    _ => Err(Malformed),
                }
            }
            // A date (section 4.2.9) is an integer.
            b'@' => {
                self.at += 1;
                match self.number()? {
                    Number::Integer(_) => Ok(Value::Other),
                    Number::Decimal => Err(Malformed),
                }
            }
            b'%' => {
                self.at += 1;
                self.display_string()?;
                Ok(Value::Other)
            }
            _ => Err(Malformed),
        }
    }

    /// Section 4.2.4: at most 15 digits for an integer, and for a decimal at most 12 before its
    /// point and from 1 to 3 after it.
    fn number(&mut self) -> Result<Number, Malformed> {
        let negative = self.eat(b'-');
        let start = self.at;
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(Malformed);
        }
        let mut point = None;
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' => {}
                b'.' if point.is_none() => {
                    if self.at - start > 12 {
                        return Err(Malformed);
                    }
                    point = Some(self.at);
                }
                _ => break,
            }
            self.at += 1;
            let len = self.at - start;
            if len > if point.is_some() { 16 } else { 15 } {
                return Err(Malformed);
            }
        }
        let Some(point) = point else {
            // At most 15 digits: the value is below 10^15.
            let value = self.input[start..self.at]
                .iter()
                .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'));
            return Ok(Number::Integer(if negative { -value } else { value }));
        };
        match self.at - point - 1 {
            1..=3 => Ok(Number::Decimal),
            _ => Err(Malformed),
        }
    }

    /// Section 4.2.5, after the opening quote.
    fn string(&mut self) -> Result<(), Malformed> {
        loop {
            match self.next()? {
                b'\\' => {
                    if !matches!(self.next()?, b'"' | b'\\') {
                        return Err(Malformed);
                    }
                }
                b'"' => return Ok(()),
                0x00..=0x1f | 0x7f..=0xff => return Err(Malformed),
                _ => {}
            }
        }
    }

    /// Section 4.2.6, from its first character, which the caller checked.
    fn token(&mut self) {
        self.at += 1;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&byte))
        {
            self.at += 1;
        }
    }

    /// Section 4.2.7, after the opening colon: base64 of RFC 4648, section 4. Padding is a suffix,
    /// and it can be missing or longer than needed: the parser does not fail on them, as the
    /// section says it should not. One symbol alone in the last group decodes to no byte, so it
    /// fails.
    fn bytes(&mut self) -> Result<(), Malformed> {
        let rest = &self.input[self.at..];
        let end = rest.iter().position(|&byte| byte == b':').ok_or(Malformed)?;
        let content = &rest[..end];
        self.at += end + 1;
        let symbols = content.iter().position(|&byte| byte == b'=').unwrap_or(content.len());
        let (data, padding) = content.split_at(symbols);
        let valid = data
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            && padding.iter().all(|&byte| byte == b'=')
            && data.len() % 4 != 1;
        if valid { Ok(()) } else { Err(Malformed) }
    }

    /// Section 4.2.10, after the `%`: a quoted string of printable ASCII and percent-encoded bytes,
    /// which decode to UTF-8.
    fn display_string(&mut self) -> Result<(), Malformed> {
        if !self.eat(b'"') {
            return Err(Malformed);
        }
        let mut utf8 = Utf8::default();
        loop {
            let byte = match self.next()? {
                b'"' if utf8.complete() => return Ok(()),
                b'%' => {
                    let hex = |byte: u8| match byte {
                        b'0'..=b'9' => Ok(byte - b'0'),
                        b'a'..=b'f' => Ok(byte - b'a' + 10),
                        _ => Err(Malformed),
                    };
                    (hex(self.next()?)? << 4) | hex(self.next()?)?
                }
                byte @ 0x20..=0x7e if byte != b'"' => byte,
                _ => return Err(Malformed),
            };
            if !utf8.push(byte) {
                return Err(Malformed);
            }
        }
    }
}

/// A check of UTF-8 one byte at a time: the well-formed sequences of the Unicode Standard,
/// table 3-7.
#[derive(Default)]
struct Utf8 {
    /// The continuation bytes that the sequence still needs.
    needs: u8,
    /// The range of the next continuation byte.
    low: u8,
    high: u8,
}

impl Utf8 {
    /// Takes the next byte. Gives `false` when the bytes are not UTF-8.
    fn push(&mut self, byte: u8) -> bool {
        if self.needs == 0 {
            (self.needs, self.low, self.high) = match byte {
                0x00..=0x7f => return true,
                0xc2..=0xdf => (1, 0x80, 0xbf),
                0xe0 => (2, 0xa0, 0xbf),
                0xe1..=0xec | 0xee..=0xef => (2, 0x80, 0xbf),
                0xed => (2, 0x80, 0x9f),
                0xf0 => (3, 0x90, 0xbf),
                0xf1..=0xf3 => (3, 0x80, 0xbf),
                0xf4 => (3, 0x80, 0x8f),
                _ => return false,
            };
            return true;
        }
        if !(self.low..=self.high).contains(&byte) {
            return false;
        }
        (self.needs, self.low, self.high) = (self.needs - 1, 0x80, 0xbf);
        true
    }

    /// Whether the bytes end at the end of a sequence.
    const fn complete(&self) -> bool {
        self.needs == 0
    }
}
