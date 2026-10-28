//! RFC 1459 message parsing and serialisation.
//!
//! The parser accepts the RFC 2812 grammar as well as the IRCv3 extensions
//! that real clients send: message tags (`@key=value`), 15 parameters
//! maximum, and the `:`-prefixed trailing parameter. Every accepted line is
//! capped at a caller-supplied length (512 bytes on the wire by default,
//! including `CRLF`).

use std::fmt;

// MARK: protocol: medium: PROTO-PARAMS-001: 15-parameter ceiling from RFC 1459 section 2.3.1.
/// Maximum number of parameters a single message may carry (RFC 1459 §2.3.1).
pub const MAX_PARAMS: usize = 15;

/// Default maximum wire length of a message, including the trailing `CRLF`.
pub const DEFAULT_MAX_LINE: usize = 512;

/// Ceiling on the client-only tags one message may add.
///
/// The IRCv3 limit for a tag section is 8191 bytes; a smaller budget keeps a
/// tag flood from crowding out the message itself.
pub const MAX_CLIENT_TAG_BYTES: usize = 4096;

/// A parsed IRC message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// IRCv3 message tags, in wire order.
    pub tags: Vec<(String, String)>,
    /// Optional source prefix, without the leading `:`.
    pub prefix: Option<String>,
    /// Command or three-digit numeric, upper-cased for alphabetic commands.
    pub command: String,
    /// Parameters, with the trailing parameter stored without its `:` marker.
    pub params: Vec<String>,
}

/// Reasons a line can fail to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The line contained no bytes.
    #[error("empty message")]
    Empty,
    /// No command verb was present.
    #[error("missing command")]
    MissingCommand,
    /// A command contained characters outside `[A-Za-z0-9]`.
    #[error("invalid command {0:?}")]
    InvalidCommand(String),
    /// More than [`MAX_PARAMS`] parameters were supplied.
    #[error("too many parameters (max {MAX_PARAMS})")]
    TooManyParams,
    /// The line exceeded the negotiated length limit.
    #[error("message too long: {0} bytes")]
    TooLong(usize),
    /// A message tag was not of the form `key` or `key=value`.
    #[error("invalid message tag")]
    InvalidTag,
    /// The line carried a control character the protocol forbids.
    #[error("control character in message")]
    InvalidControl,
}

impl Message {
    /// Construct an empty message with `command`.
    pub fn command(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            ..Self::default()
        }
    }

    /// Construct a message with parameters.
    pub fn with_params<I, S>(command: impl Into<String>, params: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            command: command.into(),
            params: params.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Add a tag, replacing any existing tag with the same key.
    pub fn push_tag(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        match self.tags.iter_mut().find(|(existing, _)| *existing == key) {
            Some(slot) => slot.1 = value,
            None => self.tags.push((key, value)),
        }
    }

    /// Parse a single line, rejecting anything longer than `max_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the line is empty, over-long, has a
    /// malformed command or tag, or carries too many parameters.
    pub fn parse(raw: &str, max_len: usize) -> Result<Self, ParseError> {
        let line = raw.trim_end_matches(['\r', '\n', '\0']);
        // MARK: security: critical: SEC-CONTROL-001: rejects C0/DEL before copying any field.
        // RFC 1459 §2.3 forbids NUL, CR and LF inside a message, and every
        // implementation treats the other C0 bytes as line noise. Rejecting
        // them at the edge is what stops a client from injecting parameters or
        // whole lines into everything the server later relays on its behalf,
        // including server-to-server traffic and script output.
        if line.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(ParseError::InvalidControl);
        }
        // A client may spend the IRCv3 tag budget on top of the line limit, but
        // only the tag section: the rest of the message stays inside `max_len`.
        let limit = if line.starts_with('@') {
            max_len.saturating_add(MAX_CLIENT_TAG_BYTES)
        } else {
            max_len
        };
        if line.len() > limit {
            return Err(ParseError::TooLong(line.len()));
        }
        if let Some(tags) = line.strip_prefix('@') {
            if let Some((block, rest)) = tags.split_once(' ') {
                if block.len() > MAX_CLIENT_TAG_BYTES || rest.len() > max_len {
                    return Err(ParseError::TooLong(line.len()));
                }
            }
        }
        if line.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut rest = line.trim_start_matches(' ');
        let mut message = Message::default();

        if let Some(tag_block) = rest.strip_prefix('@') {
            let (tags, tail) = split_word(tag_block);
            if tags.is_empty() {
                return Err(ParseError::InvalidTag);
            }
            parse_tags(tags, &mut message.tags)?;
            rest = tail.trim_start_matches(' ');
        }

        if let Some(prefix_block) = rest.strip_prefix(':') {
            let (prefix, tail) = split_word(prefix_block);
            if prefix.is_empty() {
                return Err(ParseError::MissingCommand);
            }
            message.prefix = Some(prefix.to_owned());
            rest = tail.trim_start_matches(' ');
        }

        let (command, mut tail) = split_word(rest);
        if command.is_empty() {
            return Err(ParseError::MissingCommand);
        }
        if !command
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || b.is_ascii_digit())
        {
            return Err(ParseError::InvalidCommand(command.to_owned()));
        }
        message.command = command.to_ascii_uppercase();

        while !tail.is_empty() {
            if message.params.len() == MAX_PARAMS {
                return Err(ParseError::TooManyParams);
            }
            if let Some(trailing) = tail.strip_prefix(':') {
                message.params.push(trailing.to_owned());
                break;
            }
            let (word, next) = split_word(tail);
            message.params.push(word.to_owned());
            tail = next.trim_start_matches(' ');
        }

        Ok(message)
    }

    // MARK: security: high: SEC-TAG-001: relays only `+` tags and allowlisted vendor tags.
    /// Client tags this message is allowed to relay.
    ///
    /// `+`-prefixed keys are always accepted; a vendor tag without the prefix is
    /// accepted only when `allowlist` names it exactly. Server tags such as
    /// `time`, `account` and `label` are therefore never spoofable. Names are
    /// validated and the total size is capped, so a hostile client cannot smuggle
    /// arbitrary keys or unbounded data into the relay.
    pub fn client_tags(&self, allowlist: &[String]) -> Vec<(String, String)> {
        let mut total = 0usize;
        let mut tags = Vec::new();
        for (key, value) in &self.tags {
            let allowed = match key.strip_prefix('+') {
                Some(name) => valid_tag_key(name),
                // Vendor tags are operator policy: an exact match is the only
                // way one is accepted without the `+` prefix.
                None => allowlist.iter().any(|entry| entry == key),
            };
            if !allowed {
                continue;
            }
            total += key.len() + value.len() + 2;
            if total > MAX_CLIENT_TAG_BYTES {
                break;
            }
            tags.push((key.clone(), value.clone()));
        }
        tags
    }

    /// Parameter at `index`, if present.
    #[inline]
    pub fn param(&self, index: usize) -> Option<&str> {
        self.params.get(index).map(String::as_str)
    }

    /// The trailing parameter (the last one), if present.
    #[inline]
    pub fn trailing(&self) -> Option<&str> {
        self.params.last().map(String::as_str)
    }

    // MARK: speed: medium: SPD-SER-001: single pass into the caller's buffer.
    /// Serialise the message into `out`, appending the terminating `CRLF`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        if !self.tags.is_empty() {
            out.push(b'@');
            for (index, (key, value)) in self.tags.iter().enumerate() {
                if index > 0 {
                    out.push(b';');
                }
                escape_tag(key, out);
                if !value.is_empty() {
                    out.push(b'=');
                    escape_tag(value, out);
                }
            }
            out.push(b' ');
        }
        if let Some(prefix) = &self.prefix {
            out.push(b':');
            out.extend_from_slice(prefix.as_bytes());
            out.push(b' ');
        }
        out.extend_from_slice(self.command.as_bytes());
        for (index, param) in self.params.iter().enumerate() {
            out.push(b' ');
            let is_last = index + 1 == self.params.len();
            let needs_colon =
                is_last && (param.is_empty() || param.contains(' ') || param.starts_with(':'));
            if needs_colon {
                out.push(b':');
            }
            out.extend_from_slice(param.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }

    // MARK: security: medium: SEC-LEN-001: clamps the ceiling so output stays terminated.
    /// Serialise the message, truncating the trailing parameter so the encoded
    /// line (including `CRLF`) never exceeds `max_len` bytes.
    ///
    /// Truncation only ever shortens the final parameter, which is the
    /// behaviour mandated by RFC 1459 §2.3 and avoids sending split lines.
    pub fn to_bytes_limited(&self, max_len: usize) -> Vec<u8> {
        // A terminated line needs at least the two bytes of `CRLF`; a smaller
        // ceiling cannot be met, so it is raised rather than emitting an
        // unterminated fragment.
        let max_len = max_len.max(2);
        let mut out = Vec::with_capacity(max_len.min(512));
        self.write_to(&mut out);
        if out.len() <= max_len {
            return out;
        }
        let mut truncated = self.clone();
        if truncated.params.is_empty() {
            out.truncate(max_len.saturating_sub(2));
            out.extend_from_slice(b"\r\n");
            return out;
        }
        let mut ceiling = truncated.params.last().map_or(0, String::len);
        loop {
            out.clear();
            truncated.write_to(&mut out);
            if out.len() <= max_len || ceiling == 0 {
                if out.len() > max_len {
                    // Only reachable when the command and parameters alone
                    // exceed the limit; keep the line terminated.
                    out.truncate(max_len.saturating_sub(2));
                    out.extend_from_slice(b"\r\n");
                }
                return out;
            }
            let excess = out.len() - max_len;
            ceiling = ceiling.saturating_sub(excess.max(1));
            if let Some(last) = truncated.params.last_mut() {
                // Never split a UTF-8 code point: trim to the nearest boundary.
                while ceiling > 0 && !last.is_char_boundary(ceiling) {
                    ceiling -= 1;
                }
                last.truncate(ceiling);
            }
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(64);
        self.write_to(&mut bytes);
        let text = String::from_utf8_lossy(&bytes);
        f.write_str(text.trim_end_matches("\r\n"))
    }
}

/// True when `key` is a syntactically valid tag name without its prefix.
fn valid_tag_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'/'))
}

/// Split the first space-delimited word from the rest, returning the remainder
/// with a single leading space removed.
#[inline]
fn split_word(input: &str) -> (&str, &str) {
    match input.find(' ') {
        Some(index) => (&input[..index], &input[index + 1..]),
        None => (input, ""),
    }
}

fn parse_tags(block: &str, out: &mut Vec<(String, String)>) -> Result<(), ParseError> {
    for tag in block.split(';') {
        if tag.is_empty() {
            continue;
        }
        let (key, value) = match tag.split_once('=') {
            Some((key, value)) => (key, unescape_tag(value).ok_or(ParseError::InvalidTag)?),
            None => (tag, String::new()),
        };
        if key.is_empty() {
            return Err(ParseError::InvalidTag);
        }
        out.push((key.to_owned(), value));
    }
    Ok(())
}

/// Decode the IRCv3 tag escape sequences. Returns `None` on a dangling `\`.
fn unescape_tag(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            ':' => out.push(';'),
            's' => out.push(' '),
            '\\' => out.push('\\'),
            'r' => out.push('\r'),
            'n' => out.push('\n'),
            other => out.push(other),
        }
    }
    Some(out)
}

fn escape_tag(value: &str, out: &mut Vec<u8>) {
    for byte in value.bytes() {
        match byte {
            b';' => out.extend_from_slice(b"\\:"),
            b' ' => out.extend_from_slice(b"\\s"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_budget_is_additive_but_the_body_is_not() {
        let tags = format!("@{}", "+k=v;".repeat(200));
        let line = format!("{tags} PRIVMSG #chan :hello");
        assert!(line.len() > DEFAULT_MAX_LINE);
        assert!(Message::parse(&line, DEFAULT_MAX_LINE).is_ok());

        // The body alone still has to fit the ordinary limit.
        let long_body = format!("@+k=v PRIVMSG #chan :{}", "x".repeat(DEFAULT_MAX_LINE));
        assert!(Message::parse(&long_body, DEFAULT_MAX_LINE).is_err());

        // So does an over-budget tag section.
        let huge = format!("@{}", "+k=v;".repeat(MAX_CLIENT_TAG_BYTES));
        assert!(Message::parse(&format!("{huge} PING x"), DEFAULT_MAX_LINE).is_err());
    }

    #[test]
    fn parses_command_with_trailing() {
        let message = Message::parse("PRIVMSG #chan :hello world\r\n", DEFAULT_MAX_LINE)
            .expect("valid message");
        assert_eq!(message.command, "PRIVMSG");
        assert_eq!(message.params, vec!["#chan", "hello world"]);
        assert!(message.prefix.is_none());
    }

    #[test]
    fn parses_prefix_and_case_insensitive_command() {
        let message =
            Message::parse(":alice!a@b privmsg bob :hi", DEFAULT_MAX_LINE).expect("valid");
        assert_eq!(message.prefix.as_deref(), Some("alice!a@b"));
        assert_eq!(message.command, "PRIVMSG");
        assert_eq!(message.params, vec!["bob", "hi"]);
    }

    #[test]
    fn parses_tags_with_escapes() {
        let message = Message::parse(
            "@time=2020-01-01T00:00:00Z;msg=one\\stwo\\:three PRIVMSG #c :x",
            DEFAULT_MAX_LINE,
        )
        .expect("valid");
        assert_eq!(
            message.tags,
            vec![
                ("time".to_owned(), "2020-01-01T00:00:00Z".to_owned()),
                ("msg".to_owned(), "one two;three".to_owned())
            ]
        );
    }

    #[test]
    fn rejects_overlong_and_invalid_lines() {
        assert_eq!(Message::parse("", 512), Err(ParseError::Empty));
        assert_eq!(Message::parse("PRIVMSG", 3), Err(ParseError::TooLong(7)));
        assert!(matches!(
            Message::parse("@ PRIVMSG #c :x", 512),
            Err(ParseError::InvalidTag)
        ));
        assert!(matches!(
            Message::parse("PR1V-MSG a", 512),
            Err(ParseError::InvalidCommand(_))
        ));
    }

    #[test]
    fn rejects_sixteenth_parameter() {
        let line = format!(
            "CMD {}",
            (0..16)
                .map(|i| format!("p{i}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(Message::parse(&line, 512), Err(ParseError::TooManyParams));
    }

    #[test]
    fn round_trips_trailing_and_empty_params() {
        let original = Message::with_params("PRIVMSG", ["#chan", "hello world"]);
        let mut bytes = Vec::new();
        original.write_to(&mut bytes);
        let text = String::from_utf8(bytes).expect("utf8");
        assert_eq!(text, "PRIVMSG #chan :hello world\r\n");
        assert_eq!(
            Message::parse(&text, DEFAULT_MAX_LINE).expect("reparse"),
            original
        );
    }

    #[test]
    fn truncates_to_wire_limit() {
        let message = Message::with_params("PRIVMSG", vec!["#chan".to_owned(), "x".repeat(600)]);
        let bytes = message.to_bytes_limited(DEFAULT_MAX_LINE);
        assert!(bytes.len() <= DEFAULT_MAX_LINE);
        assert!(bytes.ends_with(b"\r\n"));
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(
            Message::parse("PRIVMSG #c :a\rb", DEFAULT_MAX_LINE),
            Err(ParseError::InvalidControl)
        );
        assert_eq!(
            Message::parse("PRIVMSG #c :a\0b", DEFAULT_MAX_LINE),
            Err(ParseError::InvalidControl)
        );
        assert_eq!(
            Message::parse("PRIVMSG #c :a\tb", DEFAULT_MAX_LINE),
            Err(ParseError::InvalidControl)
        );
        // The terminator itself is still trimmed, not rejected.
        assert!(Message::parse("PING x\r\n", DEFAULT_MAX_LINE).is_ok());
    }

    #[test]
    fn tiny_limits_keep_the_line_terminated() {
        let message = Message::with_params("PING", ["payload"]);
        for limit in 0..4 {
            let bytes = message.to_bytes_limited(limit);
            assert!(bytes.len() <= limit.max(2), "{limit} produced {bytes:?}");
            assert!(bytes.ends_with(b"\r\n"));
        }
    }

    #[test]
    fn display_omits_crlf() {
        let message = Message::with_params("PING", ["abc"]);
        assert_eq!(message.to_string(), "PING abc");
    }
}
