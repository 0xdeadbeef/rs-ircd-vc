//! Channel membership and mode state.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::server::client::ClientId;
use crate::util::{now_unix, wildcard_match};

/// Per-member status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemberMode {
    /// Channel operator (`+o`).
    pub op: bool,
    /// Voice (`+v`).
    pub voice: bool,
}

impl MemberMode {
    /// Status prefixes for this member honouring `multi-prefix`.
    pub fn prefixes(self, multi_prefix: bool) -> String {
        let mut out = String::with_capacity(2);
        if self.op {
            out.push('@');
            if !multi_prefix {
                return out;
            }
        }
        if self.voice {
            out.push('+');
        }
        out
    }

    /// True when the member may speak in a moderated channel.
    pub fn can_speak(self) -> bool {
        self.op || self.voice
    }
}

/// A channel ban or exception entry.
///
/// A mask matches `nick!user@host`, a bare nickname or `user@host`. The prefix
/// `$a:` selects an account instead, which is how a ban follows a user across
/// nick and host changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    /// Mask such as `*!*@example.com` or `$a:alice`.
    pub mask: String,
    /// Who set it.
    pub set_by: String,
    /// When it was set (Unix seconds).
    pub set_at: u64,
}

impl BanEntry {
    /// True when this entry covers the given user.
    ///
    /// `$a:<pattern>` entries match the SASL account name, case-insensitively
    /// and with wildcards, so `$a:*` matches every authenticated user. All
    /// other entries match the nickname, `user@host` and the complete mask.
    pub fn matches(&self, nick: &str, user: &str, host: &str, account: Option<&str>) -> bool {
        self.matches_mask(
            nick,
            &format!("{nick}!{user}@{host}"),
            &format!("{user}@{host}"),
            account,
        )
    }

    /// Same test as [`BanEntry::matches`], with the derived masks supplied by
    /// the caller.
    ///
    /// A channel with `n` bans used to build `2n` strings for one check. The
    /// caller now builds both masks once and every entry compares against the
    /// same slices, which matters on `JOIN` and `PRIVMSG` paths where the list
    /// is walked per message.
    pub fn matches_mask(
        &self,
        nick: &str,
        full: &str,
        user_host: &str,
        account: Option<&str>,
    ) -> bool {
        if let Some(pattern) = self.mask.strip_prefix("$a:") {
            return account.is_some_and(|account| {
                wildcard_match(&pattern.to_ascii_lowercase(), &account.to_ascii_lowercase())
            });
        }
        wildcard_match(&self.mask, full)
            || wildcard_match(&self.mask, nick)
            || wildcard_match(&self.mask, user_host)
    }
}

/// A channel and its members.
#[derive(Debug)]
pub struct Channel {
    /// Name as created, including its `#`/`&` prefix.
    pub name: String,
    /// Creation time (Unix seconds).
    pub created: u64,
    /// Topic, if set.
    pub topic: Option<String>,
    /// Nick that last set the topic.
    pub topic_setter: Option<String>,
    /// When the topic was set (Unix seconds).
    pub topic_time: u64,
    /// `+k` key.
    pub key: Option<String>,
    /// `+l` member limit.
    pub limit: Option<usize>,
    /// `+i`: only invited clients may join.
    pub invite_only: bool,
    /// `+m`: only voiced/op members may speak.
    pub moderated: bool,
    /// `+n`: outsiders may not send to the channel.
    pub no_external: bool,
    /// `+s`: hidden from `LIST`/`WHOIS` for non-members.
    pub secret: bool,
    /// `+p`: private.
    pub private: bool,
    /// `+t`: only operators may change the topic.
    pub topic_lock: bool,
    /// `+R`: only authenticated users may join or speak.
    pub account_only: bool,
    /// Members keyed by client id.
    pub members: HashMap<ClientId, MemberMode>,
    /// Ban list.
    pub bans: Vec<BanEntry>,
    /// `+e` ban exceptions; a matching user is not banned.
    pub exceptions: Vec<BanEntry>,
    /// Outstanding invitations, keyed by client id.
    pub invites: HashMap<ClientId, Invite>,
}

/// One outstanding channel invitation.
#[derive(Debug, Clone)]
pub struct Invite {
    /// Nickname of the user who issued it, used for the expiry notice.
    pub by: String,
    /// When the invitation stops being valid.
    pub expires: Instant,
    /// Whether the pre-expiry warning has already been delivered.
    pub warned: bool,
}

/// What a sweep found for one invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteDue {
    /// Client the invitation belongs to.
    pub invitee: ClientId,
    /// Nickname of the user who issued it.
    pub by: String,
    /// Whole seconds left; zero once the invitation has lapsed.
    pub seconds_left: u64,
    /// True when the invitation has lapsed and was removed.
    pub expired: bool,
}

impl Channel {
    /// Create an empty channel with the modes RFC 2811 recommends by default.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            created: now_unix(),
            topic: None,
            topic_setter: None,
            topic_time: 0,
            key: None,
            limit: None,
            invite_only: false,
            moderated: false,
            no_external: true,
            secret: false,
            private: false,
            topic_lock: true,
            account_only: false,
            members: HashMap::new(),
            bans: Vec::new(),
            exceptions: Vec::new(),
            invites: HashMap::new(),
        }
    }

    /// Add a member; the first member becomes an operator.
    pub fn add(&mut self, id: ClientId) -> MemberMode {
        let mode = MemberMode {
            op: self.members.is_empty(),
            voice: false,
        };
        self.members.insert(id, mode);
        self.invites.remove(&id);
        mode
    }

    /// Remove a member, returning whether they were present.
    pub fn remove(&mut self, id: ClientId) -> bool {
        self.members.remove(&id).is_some()
    }

    /// Record an invitation issued by `by` that lapses after `ttl`.
    pub fn invite(&mut self, id: ClientId, by: impl Into<String>, ttl: Duration) {
        self.invites.insert(
            id,
            Invite {
                by: by.into(),
                expires: Instant::now() + ttl,
                warned: false,
            },
        );
    }

    /// True when `id` holds an unexpired invitation, judged at `now`.
    pub fn invited_at(&self, id: ClientId, now: Instant) -> bool {
        self.invites
            .get(&id)
            .is_some_and(|invite| invite.expires > now)
    }

    /// True when `id` holds an unexpired invitation.
    pub fn invited(&self, id: ClientId) -> bool {
        self.invited_at(id, Instant::now())
    }

    /// Drop any invitation held by `id`.
    pub fn withdraw_invite(&mut self, id: ClientId) {
        self.invites.remove(&id);
    }

    /// Report invitations that need a notice and remove the ones that lapsed.
    ///
    /// An invitation inside `warn_before` of expiry is reported once and then
    /// marked, so later sweeps stay quiet. Expired entries are removed and
    /// reported, which keeps the notice truthful: [`Channel::invited`] refuses
    /// them from that moment on. A zero `warn_before` disables the warning.
    pub fn sweep_invites(&mut self, now: Instant, warn_before: Duration) -> Vec<InviteDue> {
        let mut due = Vec::new();
        self.invites.retain(|invitee, invite| {
            if invite.expires <= now {
                due.push(InviteDue {
                    invitee: *invitee,
                    by: invite.by.clone(),
                    seconds_left: 0,
                    expired: true,
                });
                return false;
            }
            if !invite.warned {
                let left = invite.expires.saturating_duration_since(now);
                if left <= warn_before {
                    invite.warned = true;
                    due.push(InviteDue {
                        invitee: *invitee,
                        by: invite.by.clone(),
                        seconds_left: left.as_secs(),
                        expired: false,
                    });
                }
            }
            true
        });
        due
    }

    /// Membership status for `id`.
    pub fn member(&self, id: ClientId) -> Option<MemberMode> {
        self.members.get(&id).copied()
    }

    /// True when `id` is a channel operator.
    pub fn is_op(&self, id: ClientId) -> bool {
        self.members.get(&id).is_some_and(|mode| mode.op)
    }

    /// True when `id` is a member.
    pub fn contains(&self, id: ClientId) -> bool {
        self.members.contains_key(&id)
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// True when the channel has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// True when a ban covers this user and no exception excuses them.
    ///
    /// Exceptions are checked first, which is what makes `+e` an escape hatch
    /// from a wide ban without having to split the ban mask.
    pub fn is_banned(&self, nick: &str, user: &str, host: &str, account: Option<&str>) -> bool {
        if self.bans.is_empty() {
            return false;
        }
        let full = format!("{nick}!{user}@{host}");
        let user_host = format!("{user}@{host}");
        let matches = |entry: &BanEntry| entry.matches_mask(nick, &full, &user_host, account);
        self.bans.iter().any(&matches) && !self.exceptions.iter().any(matches)
    }

    /// Serialise modes for numeric `324`.
    ///
    /// Keys are included because the requester must know them to join.
    pub fn mode_string(&self) -> String {
        let (mut modes, arguments) = self.burst_modes();
        for argument in arguments {
            modes.push(' ');
            modes.push_str(&argument);
        }
        modes
    }

    /// Mode flags together with their arguments, in wire order.
    ///
    /// A netburst sends one `SJOIN` per channel, so the flags and the argument
    /// list stay separable instead of being flattened into one string.
    pub fn burst_modes(&self) -> (String, Vec<String>) {
        let mut modes = String::from("+");
        for (enabled, letter) in [
            (self.invite_only, 'i'),
            (self.moderated, 'm'),
            (self.no_external, 'n'),
            (self.private, 'p'),
            (self.secret, 's'),
            (self.topic_lock, 't'),
            (self.account_only, 'R'),
        ] {
            if enabled {
                modes.push(letter);
            }
        }
        let mut arguments = Vec::new();
        if let Some(key) = &self.key {
            modes.push('k');
            arguments.push(key.clone());
        }
        if let Some(limit) = self.limit {
            modes.push('l');
            arguments.push(limit.to_string());
        }
        (modes, arguments)
    }

    /// The `CHANMODES` letters this server understands, for `005`.
    pub const LETTERS: &'static str = "imnpstRklovbe";

    /// Members sorted by nickname for stable `NAMES` output.
    pub fn sorted_members(
        &self,
        lookup: impl Fn(ClientId) -> Option<String>,
    ) -> Vec<(ClientId, MemberMode, String)> {
        let mut members: Vec<(ClientId, MemberMode, String)> = self
            .members
            .iter()
            .filter_map(|(id, mode)| lookup(*id).map(|nick| (*id, *mode, nick)))
            .collect();
        members.sort_by_key(|member| member.2.to_lowercase());
        members
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_member_becomes_operator() {
        let mut channel = Channel::new("#test");
        assert!(channel.add(1).op);
        assert!(!channel.add(2).op);
        assert!(channel.is_op(1));
        assert!(!channel.is_op(2));
        assert_eq!(channel.len(), 2);
    }

    #[test]
    fn default_modes_include_no_external_and_topic_lock() {
        let channel = Channel::new("#test");
        assert_eq!(channel.mode_string(), "+nt");
    }

    #[test]
    fn mode_string_includes_key_and_limit() {
        let mut channel = Channel::new("#test");
        channel.key = Some("sekrit".to_owned());
        channel.limit = Some(42);
        assert_eq!(channel.mode_string(), "+ntkl sekrit 42");
    }

    #[test]
    fn ban_matching_handles_masks() {
        let mut channel = Channel::new("#test");
        channel.bans.push(BanEntry {
            mask: "*!*@bad.example".to_owned(),
            set_by: "op".to_owned(),
            set_at: 0,
        });
        assert!(channel.is_banned("nick", "user", "bad.example", None));
        assert!(!channel.is_banned("nick", "user", "good.example", None));
        assert!(!channel.is_banned("bad.example", "user", "host", None));
    }

    #[test]
    fn account_bans_follow_the_account() {
        let mut channel = Channel::new("#test");
        channel.bans.push(BanEntry {
            mask: "$a:Alice".to_owned(),
            set_by: "op".to_owned(),
            set_at: 0,
        });
        assert!(channel.is_banned("other", "u", "h", Some("alice")));
        assert!(!channel.is_banned("other", "u", "h", Some("bob")));
        assert!(!channel.is_banned("other", "u", "h", None));
    }

    #[test]
    fn account_wildcards_match_any_authenticated_user() {
        let mut channel = Channel::new("#test");
        channel.bans.push(BanEntry {
            mask: "$a:*".to_owned(),
            set_by: "op".to_owned(),
            set_at: 0,
        });
        assert!(channel.is_banned("n", "u", "h", Some("anyone")));
        assert!(!channel.is_banned("n", "u", "h", None));
    }

    #[test]
    fn exceptions_lift_a_matching_ban() {
        let mut channel = Channel::new("#test");
        channel.bans.push(BanEntry {
            mask: "*!*@bad.example".to_owned(),
            set_by: "op".to_owned(),
            set_at: 0,
        });
        channel.exceptions.push(BanEntry {
            mask: "$a:alice".to_owned(),
            set_by: "op".to_owned(),
            set_at: 0,
        });
        assert!(channel.is_banned("n", "u", "bad.example", None));
        assert!(!channel.is_banned("n", "u", "bad.example", Some("alice")));
        assert!(channel.is_banned("n", "u", "bad.example", Some("bob")));
    }

    #[test]
    fn account_only_mode_is_rendered() {
        let mut channel = Channel::new("#test");
        channel.account_only = true;
        assert_eq!(channel.mode_string(), "+ntR");
    }

    #[test]
    fn burst_modes_separate_flags_from_arguments() {
        let mut channel = Channel::new("#test");
        channel.key = Some("sekrit".to_owned());
        channel.limit = Some(42);
        assert_eq!(
            channel.burst_modes(),
            (
                "+ntkl".to_owned(),
                vec!["sekrit".to_owned(), "42".to_owned()]
            )
        );
        channel.account_only = false;
        assert_eq!(channel.mode_string(), "+ntkl sekrit 42");
    }

    #[test]
    fn prefixes_respect_multi_prefix() {
        let mode = MemberMode {
            op: true,
            voice: true,
        };
        assert_eq!(mode.prefixes(true), "@+");
        assert_eq!(mode.prefixes(false), "@");
    }

    #[test]
    fn invites_are_consumed_on_join() {
        let mut channel = Channel::new("#test");
        channel.invite(7, "alice", Duration::from_secs(60));
        channel.add(7);
        assert!(!channel.invites.contains_key(&7));
    }

    #[test]
    fn invites_expire_after_their_lifetime() {
        let mut channel = Channel::new("#test");
        let now = Instant::now();
        channel.invites.insert(
            7,
            Invite {
                by: "alice".to_owned(),
                expires: now + Duration::from_secs(60),
                warned: false,
            },
        );
        assert!(channel.invited_at(7, now + Duration::from_secs(59)));
        assert!(!channel.invited_at(7, now + Duration::from_secs(61)));
        assert!(!channel.invited_at(8, now));
    }

    #[test]
    fn withdrawing_an_invite_removes_it() {
        let mut channel = Channel::new("#test");
        channel.invite(7, "alice", Duration::from_secs(60));
        channel.withdraw_invite(7);
        assert!(!channel.invited(7));
    }

    #[test]
    fn sweeping_warns_once_then_reports_the_expiry() {
        let mut channel = Channel::new("#test");
        let now = Instant::now();
        channel.invites.insert(
            7,
            Invite {
                by: "alice".to_owned(),
                expires: now + Duration::from_secs(30),
                warned: false,
            },
        );
        let warn = Duration::from_secs(10);

        assert!(channel.sweep_invites(now, warn).is_empty());

        let due = channel.sweep_invites(now + Duration::from_secs(25), warn);
        assert_eq!(due.len(), 1);
        assert!(!due[0].expired);
        assert_eq!(due[0].seconds_left, 5);
        assert_eq!(due[0].by, "alice");

        // The warning is not repeated.
        assert!(channel
            .sweep_invites(now + Duration::from_secs(26), warn)
            .is_empty());

        let due = channel.sweep_invites(now + Duration::from_secs(31), warn);
        assert_eq!(due.len(), 1);
        assert!(due[0].expired);
        assert!(channel.invites.is_empty(), "an expired grant is removed");
    }

    #[test]
    fn a_zero_warning_window_reports_only_expiry() {
        let mut channel = Channel::new("#test");
        let now = Instant::now();
        channel.invite(7, "alice", Duration::from_secs(30));
        assert!(channel.sweep_invites(now, Duration::ZERO).is_empty());
        assert!(channel
            .sweep_invites(now + Duration::from_secs(10), Duration::ZERO)
            .is_empty());
        let due = channel.sweep_invites(now + Duration::from_secs(31), Duration::ZERO);
        assert_eq!(due.len(), 1, "only the expiry is reported");
        assert!(due[0].expired);
        assert!(channel.invites.is_empty());
    }
}
