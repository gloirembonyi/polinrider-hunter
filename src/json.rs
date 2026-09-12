//! A small JSON value, parser and serializer.
//!
//! The Gemini API speaks JSON and the agent needs to read function calls out of
//! its replies and hand structured results back. Pulling in serde would break
//! the zero-dependency rule this tool is built on, and the subset needed here
//! is small: objects, arrays, strings (with escapes), numbers, booleans, null.
//! Object key order is preserved (a Vec of pairs), which keeps request bodies
//! deterministic and diffable in the transcript.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn arr(items: Vec<Json>) -> Json {
        Json::Arr(items)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// `path(&["candidates", "0", "content"])` - numeric segments index arrays.
    pub fn path(&self, segs: &[&str]) -> Option<&Json> {
        let mut cur = self;
        for s in segs {
            cur = match cur {
                Json::Arr(items) => items.get(s.parse::<usize>().ok()?)?,
                Json::Obj(_) => cur.get(s)?,
                _ => return None,
            };
        }
        Some(cur)
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self { Some(s) } else { None }
    }
    pub fn as_f64(&self) -> Option<f64> {
        if let Json::Num(n) = self { Some(*n) } else { None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Json::Bool(b) = self { Some(*b) } else { None }
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        if let Json::Arr(a) = self { Some(a) } else { None }
    }
    pub fn as_obj(&self) -> Option<&Vec<(String, Json)>> {
        if let Json::Obj(o) = self { Some(o) } else { None }
    }
    /// String value of `key`, or "" - the common case for tool arguments.
    pub fn str_of(&self, key: &str) -> String {
        self.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
    }
    pub fn u64_of(&self, key: &str, default: u64) -> u64 {
        self.get(key).and_then(|v| v.as_f64()).map(|n| n.max(0.0) as u64).unwrap_or(default)
    }
    pub fn bool_of(&self, key: &str, default: bool) -> bool {
        self.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
    }
    pub fn strings_of(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Json::Arr(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            Some(Json::Str(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        write(self, &mut out, 0, false);
        out
    }
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        write(self, &mut out, 0, true);
        out
    }
}

fn write(v: &Json, out: &mut String, depth: usize, pretty: bool) {
    let nl = |out: &mut String, d: usize| {
        if pretty {
            out.push('\n');
            for _ in 0..d {
                out.push_str("  ");
            }
        }
    };
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                out.push_str(&format!("{}", *n as i64));
            } else {
                out.push_str(&format!("{n}"));
            }
        }
        Json::Str(s) => write_str(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, depth + 1);
                write(it, out, depth + 1, pretty);
            }
            if !items.is_empty() {
                nl(out, depth);
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            out.push('{');
            for (i, (k, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, depth + 1);
                write_str(k, out);
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                write(val, out, depth + 1, pretty);
            }
            if !pairs.is_empty() {
                nl(out, depth);
            }
            out.push('}');
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(format!("trailing characters at offset {}", p.i));
    }
    Ok(v)
}

/// Parse the first JSON object or array found inside `text`, skipping any prose
/// around it - models sometimes wrap JSON in a code fence or a sentence.
pub fn parse_loose(text: &str) -> Result<Json, String> {
    if let Ok(v) = parse(text.trim()) {
        return Ok(v);
    }
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'{' || b == b'[' {
            let mut p = Parser { s: bytes, i };
            if let Ok(v) = p.value() {
                return Ok(v);
            }
        }
    }
    Err("no JSON value found".into())
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at offset {}", b as char, self.i))
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.peek() {
            None => Err("unexpected end of input".into()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(c) => Err(format!("unexpected '{}' at offset {}", c as char, self.i)),
        }
    }
    fn literal(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad literal at offset {}", self.i))
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.i += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|e| e.to_string())?;
        text.parse::<f64>().map(Json::Num).map_err(|_| format!("bad number '{text}' at offset {start}"))
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                // Surrogate pair.
                                if self.s[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo.saturating_sub(0xDC00));
                                }
                            }
                            let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => return Err(format!("bad escape '\\{}'", other as char)),
                    }
                }
                other => out.push(other),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.s.len() {
            return Err("short \\u escape".into());
        }
        let h = std::str::from_utf8(&self.s[self.i..self.i + 4]).map_err(|e| e.to_string())?;
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| "bad \\u escape".to_string())
    }
    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at offset {}", self.i)),
            }
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.expect(b':')?;
            let v = self.value()?;
            pairs.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.i)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_nested_document() {
        let text = r#"{"a":[1,2.5,-3,true,null,"x\"y\\z\n"],"b":{"c":"é😀"},"d":{}}"#;
        let v = parse(text).unwrap();
        assert_eq!(v.path(&["a", "1"]).unwrap().as_f64(), Some(2.5));
        assert_eq!(v.path(&["a", "5"]).unwrap().as_str(), Some("x\"y\\z\n"));
        assert_eq!(v.path(&["b", "c"]).unwrap().as_str(), Some("é😀"));
        let again = parse(&v.to_string()).unwrap();
        assert_eq!(v, again);
    }

    #[test]
    fn loose_parse_finds_json_inside_prose() {
        let v = parse_loose("Sure! Here it is:\n```json\n{\"ok\": true}\n```").unwrap();
        assert_eq!(v.bool_of("ok", false), true);
    }

    #[test]
    fn errors_are_reported_not_panicked() {
        assert!(parse("{\"a\": }").is_err());
        assert!(parse("[1,2").is_err());
        assert!(parse("").is_err());
    }
}
