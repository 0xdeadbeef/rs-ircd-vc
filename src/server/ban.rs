//! Network-wide server bans.
//!
//! Four ban kinds share one representation. Match masks are wildcards over the
//! usual `nick!user@host` forms, which keeps one matcher for every kind and
//! makes the semantics easy to state:
//!
//! * `K` (K-line) refuses a connection on this server only.
//! * `G` (G-line) refuses a connection network-wide.
//! * `Z` (Z-line) refuses an address network-wide, before the client can pick
//!   a nickname, so a resolved hostname cannot be used to evade it.
//! * `SHUN` accepts the connection but silently drops what the client says.
//!
//! Every entry carries an absolute expiry in Unix seconds rather than a
//! duration, so a ban set on one server means the same instant on every other
//! server regardless of when the burst reaches it. `None` means permanent.
//!
//! # Examples
//!
//! ```
//! use ircd::server::ban::{BanKind, ServerBan};
//!
//! let ban = ServerBan::new(BanKind::Gline, "*!*@bad.example", "oper", None, "abuse");
//! assert!(ban.active(1_000));
//! assert!(ban.matches("nick", "user", "bad.example", "192.0.2.1", None));
//! assert!(!ban.matches("nick", "user", "good.example", "192.0.2.2", None));
//! ```

use std::fmt;
use std::str::FromStr;

use crate::util::wildcard_match;

/// Which kind of server ban an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BanKind {
    /// Refused on this server only.
    Kline,
    /// Refused network-wide.
    Gline,
    /// Refused network-wide by address.
    Zline,
    /// Connected but silenced.
    Shun,
}

impl BanKind {
    /// Single-letter wire and `STATS` form.
    pub fn letter(self) -> char {
        match self {
            BanKind::Kline => 'K',
            BanKind::Gline => 'G',
            BanKind::Zline => 'Z',
            BanKind::Shun => 'S',
        }
    }

    /// Long name used in `STATS` and notices.
    pub fn name(self) -> &'static str {
        match self {
            BanKind::Kline => "K-Line",
            BanKind::Gline => "G-Line",
            BanKind::Zline => "Z-Line",
            BanKind::Shun => "Shun",
        }
    }

    /// True when the ban follows a user rather than an address.
    pub fn is_address(self) -> bool {
        self == BanKind::Zline
    }

    /// True when the ban blocks registration.
    pub fn blocks_registration(self) -> bool {
        matches!(self, BanKind::Kline | BanKind::Gline | BanKind::Zline)
    }

    /// True when the ban is propagated to other servers.
    ///
    /// A K-line is a local policy decision: an operator on one server must not
    /// be able to change what another server accepts unless they hold the
    /// network-wide authority a G-line expresses.
    pub fn is_global(self) -> bool {
        self != BanKind::Kline
    }

    /// Parse a kind from a name or a single letter, ignoring case.
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_uppercase().as_str() {
            "K" | "KLINE" | "K-LINE" => Some(BanKind::Kline),
            "G" | "GLINE" | "G-LINE" => Some(BanKind::Gline),
            "Z" | "ZLINE" | "Z-LINE" => Some(BanKind::Zline),
            "S" | "SHUN" => Some(BanKind::Shun),
            _ => None,
        }
    }
}

impl fmt::Display for BanKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// One server ban.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerBan {
    /// Ban kind.
    pub kind: BanKind,
    /// Wildcard over `nick!user@host`, `user@host`, host or address.
    pub mask: String,
    /// Operator that set it.
    pub set_by: String,
    /// When it was set (Unix seconds).
    pub set_at: u64,
    /// When it stops applying (Unix seconds); `None` is permanent.
    pub expires: Option<u64>,
    /// Reason shown to the refused client and in `STATS`.
    pub reason: String,
}

impl ServerBan {
    /// Build an entry, clamping the mask to a sane length and stripping
    /// surrounding whitespace.
    ///
    /// A mask is client-visible but fixed at set time; the length cap keeps a
    /// ban list from being used as a memory amplifier through the link
    /// protocol.
    pub fn new(
        kind: BanKind,
        mask: &str,
        set_by: &str,
        expires: Option<u64>,
        reason: &str,
    ) -> Self {
        let mask = mask.trim();
        let mask = mask.chars().take(128).collect::<String>();
        let reason = reason.trim();
        let reason = reason.chars().take(300).collect::<String>();
        Self {
            kind,
            mask,
            set_by: set_by.chars().take(32).collect(),
            set_at: crate::util::now_unix(),
            expires,
            reason,
        }
    }

    /// True when the ban still applies at `now`.
    pub fn active(&self, now: u64) -> bool {
        self.expires.is_none_or(|expires| expires > now)
    }

    /// True when this entry covers the described user.
    ///
    /// `address` is the peer address as text. A Z-line compares only against
    /// it; every other kind compares the full mask, `user@host` and the nick,
    /// so `*!*@host`, `user@host`, `host` and `nick` all work.
    pub fn matches(
        &self,
        nick: &str,
        user: &str,
        host: &str,
        address: &str,
        account: Option<&str>,
    ) -> bool {
        self.matches_mask(
            nick,
            &format!("{nick}!{user}@{host}"),
            &format!("{user}@{host}"),
            host,
            address,
            account,
        )
    }

    /// Same test as [`ServerBan::matches`] with the derived masks supplied by
    /// the caller.
    ///
    /// A list of `n` bans used to build `2n` strings for one check. The caller
    /// now builds both once and every entry compares against the same slices,
    /// which is what keeps a per-message shun check off the allocator.
    // MARK: speed: high: SPD-BAN-001: caller builds both masks once per check.
    pub fn matches_mask(
        &self,
        nick: &str,
        full: &str,
        user_host: &str,
        host: &str,
        address: &str,
        account: Option<&str>,
    ) -> bool {
        if self.kind.is_address() {
            return wildcard_match(&self.mask, address) || wildcard_match(&self.mask, host);
        }
        wildcard_match(&self.mask, full)
            || wildcard_match(&self.mask, user_host)
            || wildcard_match(&self.mask, host)
            || wildcard_match(&self.mask, nick)
            || account.is_some_and(|account| {
                self.mask
                    .strip_prefix("$a:")
                    .is_some_and(|pattern| wildcard_match(pattern, account))
            })
    }

    /// Remaining lifetime in seconds, or `None` for a permanent ban.
    pub fn remaining(&self, now: u64) -> Option<u64> {
        self.expires.map(|expires| expires.saturating_sub(now))
    }
}

/// Parse a duration such as `30m`, `2h`, `7d` or `0` (permanent).
///
/// # Errors
///
/// Returns a human-readable reason when the text is empty, has an unknown
/// suffix or overflows.
pub fn parse_duration(text: &str) -> Result<Option<u64>, &'static str> {
    let text = text.trim();
    if text.is_empty() {
        return Err("duration is empty");
    }
    if text == "0" {
        return Ok(None);
    }
    let (digits, unit) = match text.char_indices().last() {
        Some((index, character)) if character.is_ascii_alphabetic() => {
            (&text[..index], character.to_ascii_lowercase())
        }
        _ => (text, 's'),
    };
    let value: u64 = digits.parse().map_err(|_| "duration is not a number")?;
    if value == 0 {
        return Ok(None);
    }
    let scale = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        'w' => 604_800,
        _ => return Err("duration unit must be s, m, h, d or w"),
    };
    value
        .checked_mul(scale)
        .map(Some)
        .ok_or("duration is too large")
}

/// Render a remaining lifetime for `STATS` and notices.
pub fn describe_remaining(remaining: Option<u64>) -> String {
    match remaining {
        None => "permanent".to_owned(),
        Some(0) => "expired".to_owned(),
        Some(seconds) => {
            if seconds >= 86_400 {
                format!("{}d", seconds / 86_400)
            } else if seconds >= 3_600 {
                format!("{}h", seconds / 3_600)
            } else if seconds >= 60 {
                format!("{}m", seconds / 60)
            } else {
                format!("{seconds}s")
            }
        }
    }
}

impl FromStr for BanKind {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        BanKind::parse(text).ok_or("unknown ban kind")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_parse_from_letters_and_names() {
        assert_eq!(BanKind::parse("k"), Some(BanKind::Kline));
        assert_eq!(BanKind::parse("G-LINE"), Some(BanKind::Gline));
        assert_eq!(BanKind::parse("zline"), Some(BanKind::Zline));
        assert_eq!(BanKind::parse("shun"), Some(BanKind::Shun));
        assert_eq!(BanKind::parse("q"), None);
        assert!(!BanKind::Kline.is_global());
        assert!(BanKind::Gline.is_global());
        assert!(BanKind::Zline.is_address());
        assert!(!BanKind::Shun.blocks_registration());
    }

    #[test]
    fn hosts_and_nicks_both_match() {
        let ban = ServerBan::new(BanKind::Gline, "*!*@bad.example", "oper", None, "abuse");
        assert!(ban.matches("nick", "user", "bad.example", "192.0.2.1", None));
        assert!(!ban.matches("nick", "user", "good.example", "192.0.2.1", None));

        let by_nick = ServerBan::new(BanKind::Kline, "troll", "oper", None, "spam");
        assert!(by_nick.matches("troll", "user", "host", "192.0.2.1", None));
        assert!(!by_nick.matches("troll2", "user", "host", "192.0.2.1", None));

        let by_account = ServerBan::new(BanKind::Shun, "$a:bad*", "oper", None, "spam");
        assert!(by_account.matches("n", "u", "h", "192.0.2.1", Some("baddie")));
        assert!(!by_account.matches("n", "u", "h", "192.0.2.1", Some("good")));
    }

    #[test]
    fn zline_matches_only_the_address() {
        let ban = ServerBan::new(BanKind::Zline, "192.0.2.*", "oper", None, "abuse");
        assert!(ban.matches("n", "u", "resolved.example", "192.0.2.7", None));
        // The host is compared too, so an unresolved client whose host is its
        // own address is covered; a resolved name with a different address is
        // not.
        assert!(ban.matches("n", "u", "192.0.2.7", "198.51.100.7", None));
        assert!(!ban.matches("n", "u", "resolved.example", "198.51.100.7", None));
    }

    #[test]
    fn expiry_is_absolute_and_exclusive() {
        let ban = ServerBan::new(BanKind::Gline, "*", "oper", Some(1_000), "abuse");
        assert!(ban.active(999));
        assert!(!ban.active(1_000));
        assert_eq!(ban.remaining(900), Some(100));
        assert_eq!(ban.remaining(2_000), Some(0));
        let permanent = ServerBan::new(BanKind::Gline, "*", "oper", None, "abuse");
        assert!(permanent.active(u64::MAX));
        assert_eq!(permanent.remaining(u64::MAX), None);
    }

    #[test]
    fn durations_parse_units_and_reject_junk() {
        assert_eq!(parse_duration("0"), Ok(None));
        assert_eq!(parse_duration("30"), Ok(Some(30)));
        assert_eq!(parse_duration("30s"), Ok(Some(30)));
        assert_eq!(parse_duration("5m"), Ok(Some(300)));
        assert_eq!(parse_duration("2h"), Ok(Some(7_200)));
        assert_eq!(parse_duration("1d"), Ok(Some(86_400)));
        assert_eq!(parse_duration("1w"), Ok(Some(604_800)));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("x").is_err());
        assert!(parse_duration("5y").is_err());
        assert!(parse_duration("99999999999999999999d").is_err());
    }

    #[test]
    fn masks_are_bounded() {
        let ban = ServerBan::new(
            BanKind::Gline,
            &"a".repeat(400),
            "oper",
            None,
            &"b".repeat(900),
        );
        assert_eq!(ban.mask.len(), 128);
        assert_eq!(ban.reason.len(), 300);
    }

    #[test]
    fn remaining_is_rendered_compactly() {
        assert_eq!(describe_remaining(None), "permanent");
        assert_eq!(describe_remaining(Some(0)), "expired");
        assert_eq!(describe_remaining(Some(45)), "45s");
        assert_eq!(describe_remaining(Some(120)), "2m");
        assert_eq!(describe_remaining(Some(7_200)), "2h");
        assert_eq!(describe_remaining(Some(172_800)), "2d");
    }
}
