//! RFC 1459 casemapping.
//!
//! IRC compares nicknames and channel names case-insensitively under a
//! non-ASCII-safe mapping: `A-Z` fold to lowercase, `[` maps to `{`, `]` to
//! `}`, `\` to `|` and (in the default mapping) `~` to `^`. `strict-rfc1459`
//! drops the `~` rule because it was only introduced by ircd 2.9.

use serde::{Deserialize, Serialize};

/// The three casemappings defined by RFC 1459 and its errata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseMapping {
    /// Only `A-Z` fold; used by clients that opt into `CASEMAPPING=ascii`.
    Ascii,
    /// RFC 1459 mapping, including `~` to `^`.
    #[default]
    Rfc1459,
    /// RFC 1459 mapping without the `~` rule.
    StrictRfc1459,
}

impl CaseMapping {
    /// The `CASEMAPPING` token advertised in `005`/`RPL_ISUPPORT`.
    pub fn token(self) -> &'static str {
        match self {
            CaseMapping::Ascii => "ascii",
            CaseMapping::Rfc1459 => "rfc1459",
            CaseMapping::StrictRfc1459 => "strict-rfc1459",
        }
    }

    /// Parse a `CASEMAPPING` token, returning `None` for unknown values.
    pub fn from_token(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "ascii" => Some(CaseMapping::Ascii),
            "rfc1459" => Some(CaseMapping::Rfc1459),
            "strict-rfc1459" => Some(CaseMapping::StrictRfc1459),
            _ => None,
        }
    }

    /// Fold a single byte according to the mapping.
    ///
    /// Non-ASCII bytes are passed through unchanged, matching the reference
    /// implementations which treat the wire encoding as opaque bytes.
    #[inline]
    pub fn fold_byte(self, byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte + 32,
            // The bracket mapping only exists in the RFC 1459 variants; the
            // `ascii` mapping intentionally leaves punctuation alone.
            b'[' if self != CaseMapping::Ascii => b'{',
            b']' if self != CaseMapping::Ascii => b'}',
            b'\\' if self != CaseMapping::Ascii => b'|',
            b'~' if self == CaseMapping::Rfc1459 => b'^',
            other => other,
        }
    }

    /// Fold `input` into a newly allocated [`String`].
    ///
    /// Prefer [`CaseMapping::fold_into`] on hot paths to reuse a buffer.
    pub fn fold(self, input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        self.fold_into(input, &mut out);
        out
    }

    /// Append the folded form of `input` to `out`.
    pub fn fold_into(self, input: &str, out: &mut String) {
        // `String::push` accepts a `char`; folding byte-wise keeps the exact
        // byte semantics of the reference implementations and stays ASCII
        // fast-pathed.
        out.reserve(input.len());
        for byte in input.bytes() {
            out.push(self.fold_byte(byte) as char);
        }
    }

    // MARK: speed: low: SPD-CASEMAP-001: folds byte-wise, no allocation on the hot path.
    /// Case-insensitive equality under this mapping without allocating.
    pub fn eq(self, left: &str, right: &str) -> bool {
        let (mut l, mut r) = (left.bytes(), right.bytes());
        loop {
            match (l.next(), r.next()) {
                (None, None) => return true,
                (Some(a), Some(b)) => {
                    if self.fold_byte(a) != self.fold_byte(b) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }
}

/// A channel or nickname key that is folded on construction.
///
/// Using a newtype prevents the classic bug of accidentally indexing a map
/// with a case-preserving string while it was populated with folded keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Folded {
    folded: String,
}

impl Folded {
    /// Fold `value` with `mapping`.
    pub fn new(value: &str, mapping: CaseMapping) -> Self {
        Self {
            folded: mapping.fold(value),
        }
    }

    /// Borrow the folded representation.
    pub fn as_str(&self) -> &str {
        &self.folded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding_matches_rfc1459_examples() {
        assert_eq!(CaseMapping::Rfc1459.fold("NiCk[]\\~"), "nick{}|^");
        assert_eq!(CaseMapping::StrictRfc1459.fold("NiCk[]\\~"), "nick{}|~");
        assert_eq!(CaseMapping::Ascii.fold("A[B\\"), "a[b\\");
    }

    #[test]
    fn equality_uses_mapping() {
        assert!(CaseMapping::Rfc1459.eq("Nick[1]", "nick{1}"));
        assert!(!CaseMapping::StrictRfc1459.eq("Nick~1", "nick^1"));
        assert!(CaseMapping::Ascii.eq("Nick[1]", "nick[1]"));
        assert!(!CaseMapping::Ascii.eq("Nick[1]", "nick{1}"));
    }

    #[test]
    fn length_mismatch_is_unequal() {
        assert!(!CaseMapping::Rfc1459.eq("nick", "nicka"));
        assert!(!CaseMapping::Rfc1459.eq("", "a"));
    }

    #[test]
    fn token_round_trip() {
        for mapping in [
            CaseMapping::Ascii,
            CaseMapping::Rfc1459,
            CaseMapping::StrictRfc1459,
        ] {
            assert_eq!(CaseMapping::from_token(mapping.token()), Some(mapping));
        }
        assert_eq!(CaseMapping::from_token("bogus"), None);
    }
}
