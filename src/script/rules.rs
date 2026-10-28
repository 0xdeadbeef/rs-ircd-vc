//! Compiled declarative guard rules.
//!
//! A rule is a hook, a set of wildcard conditions and an outcome. Conditions
//! compile to function pointers on fixed context fields, so evaluating a rule
//! costs one pointer call and one linear wildcard match per field: no
//! interpreter, no allocation, and nothing that grows with message size.

// MARK: policy: high: POL-RULES-001: rules run before scripts and a deny is final.
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::hooks::{HookContext, HookOutcome};
use crate::script::Hook;
use crate::util::wildcard_match;

/// Predicate over one context field: `(context, pattern) -> matches`.
///
/// A plain function pointer keeps [`Condition`] `Copy`-cheap and the rule set
/// `Send + Sync` without locking.
pub type ConditionFn = fn(&HookContext, &str) -> bool;

/// One wildcard condition on a fixed context field.
#[derive(Debug, Clone)]
pub struct Condition {
    /// Name of the field, for diagnostics.
    pub field: &'static str,
    /// Operator-supplied wildcard pattern.
    pub pattern: String,
    /// Compiled test.
    pub test: ConditionFn,
}

/// What a matching rule decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Permit and stop evaluating; the exception to a later deny.
    Allow,
    /// Refuse and send the rule's notice.
    Deny,
    /// Permit, but deliver the rule's notice.
    Notice,
}

/// A hook, its conditions and the outcome they produce.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Operator-visible name, used in logs and reports.
    pub name: String,
    /// Event this rule applies to.
    pub hook: Hook,
    /// Conditions, all of which must match.
    pub conditions: Vec<Condition>,
    /// What a match does.
    pub action: Action,
    /// Notice delivered to the client.
    pub notice: Option<String>,
}

/// Every rule loaded from `[scripting] rules`.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Load and compile rule files.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Script`] when a file cannot be read, is not valid
    /// TOML, or names an unknown hook or action. An unknown hook is an error
    /// rather than a skip: a typo would otherwise silently disable a guard.
    pub fn load(paths: &[String]) -> Result<Self> {
        let mut rules = Vec::new();
        for path in paths {
            let text = std::fs::read_to_string(path)
                .map_err(|error| Error::Script(format!("cannot read {path}: {error}")))?;
            let file: RuleFile =
                toml::from_str(&text).map_err(|error| Error::Script(format!("{path}: {error}")))?;
            for spec in file.rule {
                rules.push(compile(spec, path)?);
            }
        }
        Ok(Self { rules })
    }

    /// True when no rule is loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of loaded rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Rules in file order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluate the rules for `hook`, first match wins.
    ///
    /// `Allow` and `Deny` stop evaluation, which is what makes an exception
    /// rule effective when it is placed above a broad deny. `Notice` lets the
    /// pass continue so several advisories can apply to one command.
    pub fn evaluate(&self, hook: Hook, context: &HookContext) -> HookOutcome {
        let mut outcome = HookOutcome::default();
        for rule in &self.rules {
            if rule.hook != hook {
                continue;
            }
            if !rule
                .conditions
                .iter()
                .all(|condition| (condition.test)(context, &condition.pattern))
            {
                continue;
            }
            match rule.action {
                Action::Allow => {
                    outcome.allow = true;
                    return outcome;
                }
                Action::Deny => {
                    outcome.allow = false;
                    outcome.notice = rule.notice.clone();
                    return outcome;
                }
                Action::Notice => {
                    if rule.notice.is_some() {
                        outcome.notice = rule.notice.clone();
                    }
                }
            }
        }
        outcome
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    name: String,
    hook: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    nick: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    account: Option<String>,
    action: Action,
    #[serde(default)]
    notice: Option<String>,
}

fn compile(spec: RuleSpec, source: &str) -> Result<Rule> {
    let hook = Hook::parse(&spec.hook).ok_or_else(|| {
        Error::Script(format!(
            "{source}: rule {:?} names unknown hook {:?}",
            spec.name, spec.hook
        ))
    })?;
    if spec.action != Action::Allow && spec.notice.is_none() {
        return Err(Error::Script(format!(
            "{source}: rule {:?} needs a notice",
            spec.name
        )));
    }
    let mut conditions = Vec::with_capacity(7);
    add(&mut conditions, "command", spec.command, matches_command);
    add(&mut conditions, "nick", spec.nick, matches_nick);
    add(&mut conditions, "user", spec.user, matches_user);
    add(&mut conditions, "host", spec.host, matches_host);
    add(&mut conditions, "channel", spec.channel, matches_channel);
    add(&mut conditions, "text", spec.text, matches_text);
    add(&mut conditions, "account", spec.account, matches_account);
    Ok(Rule {
        name: spec.name,
        hook,
        conditions,
        action: spec.action,
        notice: spec.notice,
    })
}

fn add(
    conditions: &mut Vec<Condition>,
    field: &'static str,
    pattern: Option<String>,
    test: ConditionFn,
) {
    if let Some(pattern) = pattern {
        conditions.push(Condition {
            field,
            pattern,
            test,
        });
    }
}

fn matches_command(context: &HookContext, pattern: &str) -> bool {
    wildcard_match(pattern, &context.command)
}

fn matches_nick(context: &HookContext, pattern: &str) -> bool {
    wildcard_match(pattern, &context.nick)
}

fn matches_user(context: &HookContext, pattern: &str) -> bool {
    wildcard_match(pattern, &context.user)
}

fn matches_host(context: &HookContext, pattern: &str) -> bool {
    wildcard_match(pattern, &context.host)
}

fn matches_channel(context: &HookContext, pattern: &str) -> bool {
    wildcard_match(pattern, &context.channel)
}

fn matches_text(context: &HookContext, pattern: &str) -> bool {
    wildcard_match(pattern, &context.text)
}

/// `-` means "not authenticated", `*` means "any account"; anything else is a
/// case-insensitive wildcard on the account name.
fn matches_account(context: &HookContext, pattern: &str) -> bool {
    match pattern {
        "-" => context.account.is_none(),
        "*" => context.account.is_some(),
        _ => context.account.as_deref().is_some_and(|account| {
            wildcard_match(&pattern.to_ascii_lowercase(), &account.to_ascii_lowercase())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(command: &str, text: &str, account: Option<&str>) -> HookContext {
        HookContext {
            server: "irc.test".to_owned(),
            nick: "alice".to_owned(),
            user: "alice".to_owned(),
            host: "client.example".to_owned(),
            command: command.to_owned(),
            channel: "#room".to_owned(),
            text: text.to_owned(),
            account: account.map(str::to_owned),
            oper: false,
            params: Vec::new(),
        }
    }

    fn set(source: &str) -> RuleSet {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("rules.toml");
        std::fs::write(&path, source).expect("write");
        let set = RuleSet::load(&[path.to_string_lossy().into_owned()]).expect("load");
        std::mem::forget(directory);
        set
    }

    const DENY_BADWORD: &str = r#"
[[rule]]
name = "badword"
hook = "command"
command = "PRIVMSG"
text = "*badword*"
action = "deny"
notice = "That word is not welcome here"
"#;

    #[test]
    fn denies_matching_text() {
        let set = set(DENY_BADWORD);
        assert_eq!(set.len(), 1);
        let outcome = set.evaluate(Hook::Command, &context("PRIVMSG", "a badword here", None));
        assert!(!outcome.allow);
        assert_eq!(
            outcome.notice.as_deref(),
            Some("That word is not welcome here")
        );
        let allowed = set.evaluate(Hook::Command, &context("PRIVMSG", "hello", None));
        assert!(allowed.allow);
    }

    #[test]
    fn conditions_are_all_mandatory() {
        let set = set(DENY_BADWORD);
        // Different command and different hook both miss.
        assert!(
            set.evaluate(Hook::Command, &context("NOTICE", "badword", None))
                .allow
        );
        assert!(
            set.evaluate(Hook::Privmsg, &context("PRIVMSG", "badword", None))
                .allow
        );
    }

    #[test]
    fn an_allow_rule_above_a_deny_wins() {
        let set = set(&format!(
            r#"
[[rule]]
name = "vip"
hook = "command"
account = "alice"
action = "allow"

{DENY_BADWORD}
"#
        ));
        assert!(
            set.evaluate(Hook::Command, &context("PRIVMSG", "badword", Some("alice")))
                .allow
        );
        assert!(
            !set.evaluate(Hook::Command, &context("PRIVMSG", "badword", Some("bob")))
                .allow
        );
    }

    #[test]
    fn notice_rules_do_not_block() {
        let set = set(r#"
[[rule]]
name = "warn"
hook = "command"
account = "-"
action = "notice"
notice = "You are not logged in"
"#);
        let outcome = set.evaluate(Hook::Command, &context("PRIVMSG", "hi", None));
        assert!(outcome.allow);
        assert_eq!(outcome.notice.as_deref(), Some("You are not logged in"));
        assert!(set
            .evaluate(Hook::Command, &context("PRIVMSG", "hi", Some("bob")))
            .notice
            .is_none());
    }

    #[test]
    fn account_patterns_cover_wildcards() {
        let set = set(r#"
[[rule]]
name = "anyone"
hook = "join"
account = "*"
action = "notice"
notice = "welcome back"

[[rule]]
name = "stranger"
hook = "join"
account = "-"
action = "notice"
notice = "welcome"
"#);
        assert_eq!(
            set.evaluate(Hook::Join, &context("JOIN", "#room", Some("zed")))
                .notice
                .as_deref(),
            Some("welcome back")
        );
        assert_eq!(
            set.evaluate(Hook::Join, &context("JOIN", "#room", None))
                .notice
                .as_deref(),
            Some("welcome")
        );
    }

    #[test]
    fn unknown_hooks_and_missing_notices_are_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("rules.toml");
        std::fs::write(
            &path,
            r#"
[[rule]]
name = "typo"
hook = "message"
action = "deny"
notice = "no"
"#,
        )
        .expect("write");
        assert!(RuleSet::load(&[path.to_string_lossy().into_owned()]).is_err());

        std::fs::write(
            &path,
            r#"
[[rule]]
name = "silent"
hook = "join"
action = "deny"
"#,
        )
        .expect("write");
        assert!(RuleSet::load(&[path.to_string_lossy().into_owned()]).is_err());
    }

    #[test]
    fn empty_rule_file_is_inert() {
        let set = set("");
        assert!(set.is_empty());
        assert!(
            set.evaluate(Hook::Command, &context("PRIVMSG", "badword", None))
                .allow
        );
    }
}
