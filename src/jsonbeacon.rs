//! Removing a victim beacon planted inside a JSON manifest.
//!
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! One arm of this campaign targets browser wallet extensions. Rather than
//! change any code, it appends a key to the extension's `manifest.json`
//! carrying the campaign tag and a fingerprint of the machine:
//!
//! ```text
//!    "commands": {
//!       "__meta": {
//!          "_V": "A8-2925",
//!          "client_id": "<account>",
//!          "client_os": "Windows-11-...",
//!          "sid": "S-1-5-21-...",
//!          "installed_time": "2026-06-05 07:40:58"
//!       }
//!    }
//! ```
//!
//! `commands` is a real manifest key, so at a glance nothing looks wrong, and
//! every other byte of the extension is the genuine build.
//!
//! The general healer refuses JSON on purpose: it cuts to end-of-line, which in
//! a structured document leaves a dangling `"key": "` and an unparseable file.
//! This module is the exception, and it earns it by being precise - it finds the
//! object the tag sits in, matches braces to its end, and removes exactly that
//! key and its value. It removes nothing unless the block really is a
//! fingerprint, and nothing unless the result still parses as balanced JSON.

/// Fields that make a block a victim fingerprint rather than ordinary config.
///
/// A campaign tag alone is not enough to justify deleting part of somebody's
/// configuration file: the tag could be quoted in a comment, a test fixture or
/// a security note. Requiring several fingerprint fields alongside it is what
/// makes this safe to do automatically.
const FINGERPRINT: &[&str] = &[
    "client_id",
    "client_os",
    "browser_name",
    "installed_time",
    "installed_ver",
    "hash_mode",
    "ext_id",
    "ext_title",
    "\"sid\"",
];

/// How many of those must be present before we will touch the file.
const REQUIRED: usize = 3;

/// Remove every planted beacon block. `None` if there was nothing to remove.
pub fn strip(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = text.to_string();
    let mut removed_any = false;

    // A file could carry more than one. Bounded, because a stripper that cannot
    // make progress must stop rather than spin.
    for _ in 0..8 {
        match strip_once(&out) {
            Some(next) => {
                out = next;
                removed_any = true;
            }
            None => break,
        }
    }

    if !removed_any {
        return None;
    }
    if !balanced(&out) {
        // Should not happen - the cut is brace-matched - but writing a broken
        // manifest is far worse than leaving a beacon for a human to remove.
        return None;
    }
    Some(out.into_bytes())
}

fn strip_once(text: &str) -> Option<String> {
    let tag = find_campaign_tag(text)?;

    // The innermost object containing the tag, and the key that names it.
    let open = enclosing_open_brace(text, tag)?;
    let close = matching_close_brace(text, open)?;
    let body = &text[open..=close];
    if count_fingerprint_fields(body) < REQUIRED {
        return None;
    }
    let (key_start, _) = key_before(text, open)?;

    // Widen to whichever object the beacon key belongs to: if removing it would
    // leave its parent empty, that parent was planted too. `"commands": {}` is
    // valid but meaningless, and leaving it behind leaves a marker.
    let (mut cut_start, mut cut_end) = (key_start, close + 1);
    for _ in 0..4 {
        let Some(parent_open) = enclosing_open_brace(text, cut_start) else {
            break;
        };
        let Some(parent_close) = matching_close_brace(text, parent_open) else {
            break;
        };
        let remainder: String = text[parent_open + 1..cut_start]
            .chars()
            .chain(text[cut_end..parent_close].chars())
            .filter(|c| !c.is_whitespace() && *c != ',')
            .collect();
        if !remainder.is_empty() {
            break;
        }
        let Some((pk_start, _)) = key_before(text, parent_open) else {
            break;
        };
        cut_start = pk_start;
        cut_end = parent_close + 1;
    }

    // Take the separating comma with it, whichever side it is on, so the
    // surrounding object stays valid.
    let mut start = cut_start;
    let mut end = cut_end;
    let before: &str = &text[..start];
    let trimmed = before.trim_end();
    if trimmed.ends_with(',') {
        start = trimmed.len() - 1;
    } else {
        let after = &text[end..];
        let lead = after.len() - after.trim_start().len();
        if after[lead..].starts_with(',') {
            end += lead + 1;
        }
    }

    let mut result = String::with_capacity(text.len());
    result.push_str(&text[..start]);
    result.push_str(&text[end..]);
    Some(result)
}

/// Byte offset of a `A8-nnnn` / `A9-nnnn` campaign tag, if the text has one.
fn find_campaign_tag(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let is_hex = |c: u8| c.is_ascii_hexdigit();
    for i in 0..b.len().saturating_sub(6) {
        if (b[i] == b'A' || b[i] == b'a')
            && (b[i + 1] == b'8' || b[i + 1] == b'9')
            && b[i + 2] == b'-'
            && b[i + 3..i + 7].iter().all(u8::is_ascii_digit)
        {
            // Not part of a longer hex run, which is how GUIDs look.
            let left_ok = i == 0 || !(is_hex(b[i - 1]) || b[i - 1] == b'-' || b[i - 1] == b'_');
            let right_ok = i + 7 >= b.len() || !(is_hex(b[i + 7]) || b[i + 7] == b'-');
            if left_ok && right_ok && text.is_char_boundary(i) {
                return Some(i);
            }
        }
    }
    None
}

fn count_fingerprint_fields(body: &str) -> usize {
    FINGERPRINT.iter().filter(|f| body.contains(**f)).count()
}

/// Walk backwards from `pos` to the `{` that opens the object containing it.
fn enclosing_open_brace(text: &str, pos: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut depth = 0i32;
    let mut i = pos;
    while i > 0 {
        i -= 1;
        if in_string(text, i) {
            continue;
        }
        match b[i] {
            b'}' => depth += 1,
            b'{' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// The `}` that closes the object opened at `open`.
fn matching_close_brace(text: &str, open: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut depth = 0i32;
    for i in open..b.len() {
        if in_string(text, i) {
            continue;
        }
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The `"key"` immediately before an opening brace: its start and end offsets.
fn key_before(text: &str, open: usize) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let mut i = open;
    // Back over `: ` and any whitespace.
    while i > 0 && (b[i - 1] as char).is_whitespace() {
        i -= 1;
    }
    if i == 0 || b[i - 1] != b':' {
        return None;
    }
    i -= 1;
    while i > 0 && (b[i - 1] as char).is_whitespace() {
        i -= 1;
    }
    if i == 0 || b[i - 1] != b'"' {
        return None;
    }
    let key_end = i;
    i -= 1;
    // Back to the opening quote, honouring escapes.
    while i > 0 {
        i -= 1;
        if b[i] == b'"' && (i == 0 || b[i - 1] != b'\\') {
            return Some((i, key_end));
        }
    }
    None
}

/// Is the byte at `pos` inside a JSON string literal?
///
/// Counted from the start each time. That is quadratic in principle, but these
/// are manifests of a few kilobytes and clarity is worth more here than speed.
fn in_string(text: &str, pos: usize) -> bool {
    let b = text.as_bytes();
    let mut inside = false;
    let mut escaped = false;
    for (i, &c) in b.iter().enumerate() {
        if i == pos {
            return inside;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            b'\\' if inside => escaped = true,
            b'"' => inside = !inside,
            _ => {}
        }
    }
    false
}

/// A cheap sanity check that we did not cut the document in half.
fn balanced(text: &str) -> bool {
    let mut braces = 0i32;
    let mut brackets = 0i32;
    for (i, c) in text.char_indices() {
        if in_string(text, i) {
            continue;
        }
        match c {
            '{' => braces += 1,
            '}' => braces -= 1,
            '[' => brackets += 1,
            ']' => brackets -= 1,
            _ => {}
        }
        if braces < 0 || brackets < 0 {
            return false;
        }
    }
    braces == 0 && brackets == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape found in the wild, reproduced faithfully.
    const PLANTED: &str = r#"{
   "name": "Coinbase Wallet extension",
   "version": "3.136.0",
   "permissions": [ "storage", "alarms" ],
   "commands": {
      "__meta": {
         "description": "Coinbase",
         "_V": "A8-2925",
         "client_id": "someone",
         "client_os": "Windows-11-10.0.26200-SP0",
         "ext_id": "hnfanknocfeofbddgcijnmhnfnkdnaad",
         "browser_name": "Chrome",
         "sid": "S-1-5-21-1-2-3",
         "hash_mode": "new",
         "installed_time": "2026-06-05 07:40:58"
      }
   }
}"#;

    #[test]
    fn the_planted_block_and_its_empty_parent_are_removed() {
        let out = strip(PLANTED.as_bytes()).expect("should remove the beacon");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("__meta"), "beacon key survived:\n{text}");
        assert!(!text.contains("A8-2925"), "campaign tag survived:\n{text}");
        // `commands` held nothing else, so it was planted too.
        assert!(!text.contains("commands"), "empty parent left behind:\n{text}");
        // Everything legitimate is untouched, including formatting.
        assert!(text.contains(r#""name": "Coinbase Wallet extension""#));
        assert!(text.contains(r#""version": "3.136.0""#));
        assert!(text.contains(r#""permissions": [ "storage", "alarms" ]"#));
        assert!(balanced(&text), "result is not balanced:\n{text}");
        // The comma that separated the removed key went with it.
        assert!(!text.contains(",\n}"), "dangling comma:\n{text}");
    }

    #[test]
    fn a_real_commands_block_keeps_its_shortcuts() {
        let src = r#"{
   "name": "Something",
   "commands": {
      "_execute_action": { "suggested_key": { "default": "Ctrl+Shift+Y" } },
      "__meta": {
         "_V": "A9-1010",
         "client_id": "someone",
         "client_os": "Windows-11",
         "sid": "S-1-5-21-9"
      }
   }
}"#;
        let text = String::from_utf8(strip(src.as_bytes()).unwrap()).unwrap();
        assert!(!text.contains("__meta"));
        assert!(text.contains("_execute_action"), "real command removed:\n{text}");
        assert!(text.contains("commands"), "parent removed though it had content");
        assert!(balanced(&text));
    }

    #[test]
    fn a_campaign_tag_with_no_fingerprint_is_left_alone() {
        // Notes and test fixtures quote these tags. Removing part of somebody's
        // config because a string appears in it would be the worse error.
        let src = r#"{
   "name": "notes",
   "incident": { "tag": "A8-2941", "summary": "seen in a build config" }
}"#;
        assert!(strip(src.as_bytes()).is_none());
    }

    #[test]
    fn a_tag_inside_a_guid_is_not_a_campaign_tag() {
        let src = r#"{ "id": "3fa85f64-a8-2941-b3fc-2c963f66afa6", "client_id": "x",
                       "client_os": "y", "sid": "z" }"#;
        assert!(strip(src.as_bytes()).is_none());
    }

    #[test]
    fn a_clean_manifest_is_never_rewritten() {
        let src = r#"{ "name": "ok", "version": "1.0.0", "permissions": ["tabs"] }"#;
        assert!(strip(src.as_bytes()).is_none());
    }

    #[test]
    fn braces_inside_strings_do_not_confuse_the_matcher() {
        let src = r#"{
   "note": "a } inside a string { should not count",
   "commands": {
      "__meta": {
         "_V": "A8-2000",
         "client_id": "a", "client_os": "b", "sid": "c",
         "quirk": "another } here"
      }
   }
}"#;
        let text = String::from_utf8(strip(src.as_bytes()).unwrap()).unwrap();
        assert!(!text.contains("__meta"), "{text}");
        assert!(text.contains("a } inside a string { should not count"));
        assert!(balanced(&text));
    }
}
