//! Embedded scripting hooks.
//!
//! Rhai was chosen over Lua and JavaScript because it is pure Rust, needs no C
//! toolchain, and provides per-call resource limits (operations, call depth,
//! string size) which is exactly what an IRC daemon needs to host untrusted
//! operator scripts. The engine exposes no filesystem or network APIs.
//!
//! A script registers hooks by defining functions named `on_<event>`; the
//! `command` event can veto a command, rewrite the reply, or inject lines. A
//! script can also implement a brand new command by defining `cmd_<name>`.
//! Every script shares one `shared_set`/`shared_get` map, which is how scripts
//! expose helpers to each other.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rhai::{Dynamic, Engine, Map, Scope, AST};
use tracing::{debug, warn};

use crate::config::ScriptingSection;
use crate::error::{Error, Result};

/// Data handed to a hook as a single map argument.
#[derive(Debug, Clone, Default)]
pub struct HookContext {
    /// Server name.
    pub server: String,
    /// Sender nickname, empty before registration.
    pub nick: String,
    /// Sender username.
    pub user: String,
    /// Sender host.
    pub host: String,
    /// Command verb.
    pub command: String,
    /// Command parameters.
    pub params: Vec<String>,
    /// Channel name when the command targets a channel.
    pub channel: String,
    /// Trailing parameter, usually the message text.
    pub text: String,
    /// Sender is an IRC operator.
    pub oper: bool,
    /// SASL account, when the sender is authenticated.
    pub account: Option<String>,
}

impl HookContext {
    fn to_map(&self) -> Map {
        let mut map = Map::new();
        map.insert("server".into(), Dynamic::from(self.server.clone()));
        map.insert("nick".into(), Dynamic::from(self.nick.clone()));
        map.insert("user".into(), Dynamic::from(self.user.clone()));
        map.insert("host".into(), Dynamic::from(self.host.clone()));
        map.insert("command".into(), Dynamic::from(self.command.clone()));
        map.insert(
            "params".into(),
            Dynamic::from(
                self.params
                    .iter()
                    .cloned()
                    .map(Dynamic::from)
                    .collect::<rhai::Array>(),
            ),
        );
        map.insert("channel".into(), Dynamic::from(self.channel.clone()));
        map.insert("text".into(), Dynamic::from(self.text.clone()));
        map.insert("oper".into(), Dynamic::from(self.oper));
        map.insert(
            "account".into(),
            Dynamic::from(self.account.clone().unwrap_or_default()),
        );
        map
    }
}

/// What a hook decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOutcome {
    /// `false` when the hook vetoed the action.
    pub allow: bool,
    /// Lines to deliver to the issuing client.
    pub lines: Vec<String>,
    /// Optional notice to deliver to the issuing client.
    pub notice: Option<String>,
}

impl Default for HookOutcome {
    fn default() -> Self {
        Self {
            allow: true,
            lines: Vec::new(),
            notice: None,
        }
    }
}

/// Loaded scripts and their engine.
pub struct HookEngine {
    inner: Option<Inner>,
}

struct Inner {
    engine: Engine,
    scripts: Vec<AST>,
    loaded: Vec<String>,
}

impl HookEngine {
    /// Build the engine and compile every configured script.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Script`] when a script cannot be read or compiled.
    pub fn load(config: &ScriptingSection) -> Result<Self> {
        if !config.enabled || config.scripts.is_empty() {
            return Ok(Self { inner: None });
        }

        let mut engine = Engine::new();
        engine.set_max_operations(config.max_operations);
        engine.set_max_expr_depths(config.max_call_depth, config.max_call_depth);
        engine.set_max_string_size(config.max_string_size);
        engine.set_max_array_size(4096);
        engine.set_max_map_size(1024);
        engine.set_fast_operators(true);
        // Scripts must not be able to compile new code at runtime.
        engine.disable_symbol("eval");

        let shared: Arc<Mutex<HashMap<String, Dynamic>>> = Arc::new(Mutex::new(HashMap::new()));
        let store = Arc::clone(&shared);
        engine.register_fn("shared_set", move |key: &str, value: Dynamic| {
            store.lock().insert(key.to_owned(), value);
        });
        let load = Arc::clone(&shared);
        engine.register_fn("shared_get", move |key: &str| {
            load.lock().get(key).cloned().unwrap_or_default()
        });
        let exists = Arc::clone(&shared);
        engine.register_fn("shared_has", move |key: &str| {
            exists.lock().contains_key(key)
        });
        let remove = Arc::clone(&shared);
        engine.register_fn("shared_remove", move |key: &str| {
            remove.lock().remove(key).is_some()
        });

        engine.register_fn("log", |level: &str, message: &str| {
            match level.to_ascii_lowercase().as_str() {
                "error" => tracing::error!(target: "script", "{message}"),
                "warn" | "warning" => tracing::warn!(target: "script", "{message}"),
                "debug" => tracing::debug!(target: "script", "{message}"),
                "trace" => tracing::trace!(target: "script", "{message}"),
                _ => tracing::info!(target: "script", "{message}"),
            }
        });
        engine.register_fn("upper", |value: &str| value.to_uppercase());
        engine.register_fn("lower", |value: &str| value.to_lowercase());
        engine.register_fn("trim", |value: &str| value.trim().to_owned());
        engine.register_fn("contains_text", |value: &str, needle: &str| {
            value.contains(needle)
        });

        let mut scripts = Vec::with_capacity(config.scripts.len());
        let mut loaded = Vec::with_capacity(config.scripts.len());
        for path in &config.scripts {
            let text = std::fs::read_to_string(path)
                .map_err(|error| Error::Script(format!("cannot read {path}: {error}")))?;
            let ast = engine
                .compile(&text)
                .map_err(|error| Error::Script(format!("{path}: {error}")))?;
            scripts.push(ast);
            loaded.push(path.clone());
        }
        debug!(count = scripts.len(), "scripts loaded");

        Ok(Self {
            inner: Some(Inner {
                engine,
                scripts,
                loaded,
            }),
        })
    }

    /// True when at least one script is loaded.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Paths of the loaded scripts.
    pub fn loaded(&self) -> Vec<String> {
        self.inner
            .as_ref()
            .map(|inner| inner.loaded.clone())
            .unwrap_or_default()
    }

    /// Invoke every `on_<event>` handler.
    ///
    /// A handler returning `false` or a map with `allow: false` vetoes the
    /// action; returning a string or a map with `lines` injects raw output.
    pub fn run(&self, event: &str, context: &HookContext) -> HookOutcome {
        let Some(inner) = &self.inner else {
            return HookOutcome::default();
        };
        let function = format!("on_{}", event.to_ascii_lowercase());
        let payload = context.to_map();
        let mut outcome = HookOutcome::default();
        let mut scope = Scope::new();
        for script in &inner.scripts {
            if !has_function(script, &function) {
                continue;
            }
            match inner
                .engine
                .call_fn::<Dynamic>(&mut scope, script, &function, (payload.clone(),))
            {
                Ok(value) => apply_outcome(&mut outcome, value),
                Err(error) => warn!(%error, %function, "hook failed"),
            }
        }
        outcome
    }

    /// Run a script-defined command named `cmd_<name>`.
    pub fn custom_command(&self, name: &str, context: &HookContext) -> Option<HookOutcome> {
        let inner = self.inner.as_ref()?;
        let function = format!("cmd_{}", name.to_ascii_lowercase());
        let payload = context.to_map();
        let mut outcome: Option<HookOutcome> = None;
        let mut scope = Scope::new();
        for script in &inner.scripts {
            if !has_function(script, &function) {
                continue;
            }
            let entry = outcome.get_or_insert_with(HookOutcome::default);
            match inner
                .engine
                .call_fn::<Dynamic>(&mut scope, script, &function, (payload.clone(),))
            {
                Ok(value) => apply_outcome(entry, value),
                Err(error) => warn!(%error, %function, "scripted command failed"),
            }
        }
        outcome
    }
}

fn has_function(script: &AST, name: &str) -> bool {
    script
        .iter_functions()
        .any(|function| function.name == name)
}

fn apply_outcome(outcome: &mut HookOutcome, value: Dynamic) {
    if value.is_unit() {
        return;
    }
    if let Some(allow) = value.clone().try_cast::<bool>() {
        outcome.allow &= allow;
        return;
    }
    if let Some(text) = value.clone().try_cast::<String>() {
        outcome.lines.push(text);
        return;
    }
    if let Some(array) = value.clone().try_cast::<rhai::Array>() {
        for line in array {
            if let Some(text) = line.try_cast::<String>() {
                outcome.lines.push(text);
            }
        }
        return;
    }
    if let Some(map) = value.try_cast::<Map>() {
        if let Some(allow) = map
            .get("allow")
            .and_then(|value| value.clone().try_cast::<bool>())
        {
            outcome.allow &= allow;
        }
        if let Some(notice) = map
            .get("notice")
            .and_then(|value| value.clone().try_cast::<String>())
        {
            outcome.notice = Some(notice);
        }
        if let Some(lines) = map
            .get("lines")
            .and_then(|value| value.clone().try_cast::<rhai::Array>())
        {
            for line in lines {
                if let Some(text) = line.try_cast::<String>() {
                    outcome.lines.push(text);
                }
            }
        }
    }
}

impl crate::script::ScriptBackend for HookEngine {
    fn is_enabled(&self) -> bool {
        HookEngine::is_enabled(self)
    }

    fn loaded(&self) -> Vec<String> {
        HookEngine::loaded(self)
    }

    fn invoke(&self, hook: crate::script::Hook, context: &HookContext) -> HookOutcome {
        self.run(hook.name(), context)
    }

    fn custom_command(&self, name: &str, context: &HookContext) -> Option<HookOutcome> {
        HookEngine::custom_command(self, name, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with(source: &str) -> HookEngine {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("test.rhai");
        std::fs::write(&path, source).expect("write script");
        let config = ScriptingSection {
            enabled: true,
            scripts: vec![path.to_string_lossy().into_owned()],
            ..ScriptingSection::default()
        };
        // Keep the directory alive for the duration of the load.
        let engine = HookEngine::load(&config).expect("load");
        std::mem::forget(directory);
        engine
    }

    fn context() -> HookContext {
        HookContext {
            server: "irc.test".to_owned(),
            nick: "alice".to_owned(),
            command: "PRIVMSG".to_owned(),
            text: "hello".to_owned(),
            channel: "#test".to_owned(),
            ..HookContext::default()
        }
    }

    #[test]
    fn disabled_engine_is_inert() {
        let engine = HookEngine::load(&ScriptingSection::default()).expect("load");
        assert!(!engine.is_enabled());
        assert!(engine.run("command", &context()).allow);
        assert!(engine.custom_command("foo", &context()).is_none());
    }

    #[test]
    fn hook_can_veto() {
        let engine = engine_with("fn on_command(ctx) { false }");
        let outcome = engine.run("command", &context());
        assert!(!outcome.allow);
    }

    #[test]
    fn hook_can_inject_lines() {
        let engine = engine_with(
            r#"fn on_command(ctx) { #{ lines: ["NOTICE " + ctx.nick + " :blocked"], allow: false } }"#,
        );
        let outcome = engine.run("command", &context());
        assert!(!outcome.allow);
        assert_eq!(outcome.lines, vec!["NOTICE alice :blocked"]);
    }

    #[test]
    fn custom_command_is_reachable() {
        let engine = engine_with(r#"fn cmd_hello(ctx) { "NOTICE " + ctx.nick + " :hi" }"#);
        let outcome = engine.custom_command("HELLO", &context()).expect("command");
        assert!(outcome.allow);
        assert_eq!(outcome.lines, vec!["NOTICE alice :hi"]);
    }

    #[test]
    fn shared_state_crosses_scripts() {
        let directory = tempfile::tempdir().expect("temp dir");
        let first = directory.path().join("a.rhai");
        let second = directory.path().join("b.rhai");
        std::fs::write(
            &first,
            r#"fn on_join(ctx) { shared_set("seen", ctx.nick + "!"); true }"#,
        )
        .expect("write");
        std::fs::write(
            &second,
            r#"fn cmd_report(ctx) { "NOTICE " + ctx.nick + " :" + shared_get("seen") }"#,
        )
        .expect("write");
        let config = ScriptingSection {
            enabled: true,
            scripts: vec![
                first.to_string_lossy().into_owned(),
                second.to_string_lossy().into_owned(),
            ],
            ..ScriptingSection::default()
        };
        let engine = HookEngine::load(&config).expect("load");
        assert!(engine.run("join", &context()).allow);
        let outcome = engine
            .custom_command("report", &context())
            .expect("command");
        assert_eq!(outcome.lines, vec!["NOTICE alice :alice!"]);
    }

    #[test]
    fn infinite_loops_hit_the_operation_limit() {
        let engine = engine_with("fn on_command(ctx) { let x = 0; while true { x += 1; } true }");
        // The guard trips and the hook is treated as "no opinion".
        assert!(engine.run("command", &context()).allow);
    }

    #[test]
    fn broken_script_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("bad.rhai");
        std::fs::write(&path, "fn on_command( {").expect("write");
        let config = ScriptingSection {
            enabled: true,
            scripts: vec![path.to_string_lossy().into_owned()],
            ..ScriptingSection::default()
        };
        assert!(matches!(HookEngine::load(&config), Err(Error::Script(_))));
    }
}
