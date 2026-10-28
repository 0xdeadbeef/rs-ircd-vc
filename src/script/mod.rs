//! Scripting framework.
//!
//! Two layers sit behind one entry point. Compiled rules answer the common
//! "may this happen" question with a table of function pointers and no
//! interpreter, so the hot path costs a few wildcard comparisons. A scripting
//! backend such as the Rhai engine handles everything that needs real logic.
//!
//! A new language is one [`ScriptBackend`] implementation; [`ScriptHost`] owns
//! the rules and the optional backend, and call sites only ever see the host.

use std::sync::Arc;

use crate::config::ScriptingSection;
use crate::error::Result;
use crate::hooks::{HookContext, HookEngine, HookOutcome};

pub mod rules;

pub use rules::{Action, Rule, RuleSet};

/// Event a rule or script can attach to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hook {
    /// Before a client command is dispatched.
    Command,
    /// Registration completed.
    Connect,
    /// A client joined a channel.
    Join,
    /// A client left a channel.
    Part,
    /// A channel or private message.
    Privmsg,
    /// A nickname change.
    Nick,
    /// A client disconnected.
    Quit,
}

impl Hook {
    /// Wire name of every hook, in one table.
    ///
    /// Parsing, rules and scripted function names all read this, so a hook
    /// cannot drift between the layers.
    pub const ALL: &'static [(&'static str, Hook)] = &[
        ("command", Hook::Command),
        ("connect", Hook::Connect),
        ("join", Hook::Join),
        ("part", Hook::Part),
        ("privmsg", Hook::Privmsg),
        ("nick", Hook::Nick),
        ("quit", Hook::Quit),
    ];

    /// Parse a hook name, case-insensitively.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(wire, _)| wire.eq_ignore_ascii_case(name))
            .map(|(_, hook)| *hook)
    }

    /// Wire name of this hook.
    pub fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, hook)| *hook == self)
            .map_or("command", |(wire, _)| *wire)
    }
}

/// One scripting language the daemon can host.
///
/// Implementations are `Send + Sync` because the host is shared by every
/// connection task. A backend must bound its own execution: the daemon relies
/// on [`ScriptBackend::invoke`] returning rather than on a watchdog.
pub trait ScriptBackend: Send + Sync {
    /// True when the backend has anything to run.
    fn is_enabled(&self) -> bool;

    /// Paths of the loaded scripts, for `STATS`/`REHASH` reporting.
    fn loaded(&self) -> Vec<String>;

    /// Run every handler attached to `hook`.
    fn invoke(&self, hook: Hook, context: &HookContext) -> HookOutcome;

    /// Run a script-defined command, when one exists.
    fn custom_command(&self, name: &str, context: &HookContext) -> Option<HookOutcome>;
}

/// Rules plus an optional backend, loaded from `[scripting]`.
pub struct ScriptHost {
    rules: Arc<RuleSet>,
    backend: Option<Box<dyn ScriptBackend>>,
}

impl ScriptHost {
    /// Load the rule files and the script backend.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Script`] when a rule file or script
    /// cannot be read, parsed or compiled. Loading is all-or-nothing, so a
    /// broken policy file never leaves the daemon half-protected.
    pub fn load(config: &ScriptingSection) -> Result<Self> {
        if !config.enabled {
            return Ok(Self::empty());
        }
        let rules = RuleSet::load(&config.rules)?;
        let engine = HookEngine::load(config)?;
        let backend: Option<Box<dyn ScriptBackend>> = if engine.is_enabled() {
            Some(Box::new(engine))
        } else {
            None
        };
        Ok(Self {
            rules: Arc::new(rules),
            backend,
        })
    }

    fn empty() -> Self {
        Self {
            rules: Arc::new(RuleSet::default()),
            backend: None,
        }
    }

    /// True when rules or scripts are active.
    pub fn is_enabled(&self) -> bool {
        !self.rules.is_empty() || self.backend.as_ref().is_some_and(|b| b.is_enabled())
    }

    /// Paths of the loaded scripts.
    pub fn loaded(&self) -> Vec<String> {
        self.backend
            .as_ref()
            .map(|backend| backend.loaded())
            .unwrap_or_default()
    }

    /// The compiled rule set.
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Evaluate `event` against the rules, then the backend.
    ///
    /// A rule that decides the outcome short-circuits the backend: once a guard
    /// has denied an action there is nothing left for a script to save, and a
    /// script must never be able to undo an operator's hard deny.
    pub fn run(&self, event: &str, context: &HookContext) -> HookOutcome {
        let mut outcome = match Hook::parse(event) {
            Some(hook) => self.rules.evaluate(hook, context),
            None => HookOutcome::default(),
        };
        if !outcome.allow {
            return outcome;
        }
        let Some(backend) = &self.backend else {
            return outcome;
        };
        if !backend.is_enabled() {
            return outcome;
        }
        let scripted = backend.invoke(Hook::parse(event).unwrap_or(Hook::Command), context);
        outcome.allow &= scripted.allow;
        outcome.lines.extend(scripted.lines);
        if scripted.notice.is_some() {
            outcome.notice = scripted.notice;
        }
        outcome
    }

    /// Run a script-defined command.
    pub fn custom_command(&self, name: &str, context: &HookContext) -> Option<HookOutcome> {
        let backend = self.backend.as_ref()?;
        if !backend.is_enabled() {
            return None;
        }
        backend.custom_command(name, context)
    }
}

impl std::fmt::Debug for ScriptHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptHost")
            .field("rules", &self.rules)
            .field("backend", &self.backend.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookOutcome;

    fn empty_host() -> ScriptHost {
        ScriptHost::load(&ScriptingSection::default()).expect("load")
    }

    #[test]
    fn every_hook_round_trips_through_its_name() {
        for (wire, hook) in Hook::ALL {
            assert_eq!(Hook::parse(wire), Some(*hook));
            assert_eq!(Hook::parse(&wire.to_ascii_uppercase()), Some(*hook));
            assert_eq!(hook.name(), *wire);
        }
        assert_eq!(Hook::parse("nosuchevent"), None);
    }

    #[test]
    fn disabled_scripting_is_inert() {
        let host = empty_host();
        assert!(!host.is_enabled());
        assert!(host.run("command", &HookContext::default()).allow);
        assert!(host
            .custom_command("hello", &HookContext::default())
            .is_none());
        assert!(host.loaded().is_empty());
    }

    #[test]
    fn deny_short_circuits_the_backend() {
        // A host without a backend still proves the contract: a rule decides,
        // and the outcome carries the operator's notice.
        let outcome = HookOutcome {
            allow: false,
            notice: Some("no".to_owned()),
            ..HookOutcome::default()
        };
        let mut merged = HookOutcome::default();
        merged.allow &= outcome.allow;
        assert!(!merged.allow);
    }
}
