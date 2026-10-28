# Scripting hooks

Scripts are written in [Rhai](https://rhai.rs), embedded in the daemon. Rhai
was chosen over Lua and JavaScript because it is pure Rust (no C toolchain or
`unsafe` FFI), is sandboxed by design, and enforces per-call instruction and
memory limits — the properties that matter when operators load third-party
scripts into a network daemon.

Enable scripting in `ircd.toml`:

```toml
[scripting]
enabled = true
scripts = ["scripts/greet.rhai", "scripts/policy.rhai"]
rules = ["rules/policy.toml"]
max_operations = 100000
max_call_depth = 32
max_string_size = 1048576
```

## Framework

The daemon has two layers behind one entry point, `script::ScriptHost`:

| Layer | Cost per event | Used for |
|---|---|---|
| Compiled rules (`rules`) | A few wildcard comparisons, no interpreter | Guarding, vetos, notices |
| Script backend (`scripts`) | One Rhai call per script with a handler | Policy that needs real logic |

A rule decides the outcome before the backend runs, and a denial is final: a
script cannot overturn an operator's hard deny. Adding a second language means
implementing `ScriptBackend` (`is_enabled`, `loaded`, `invoke`,
`custom_command`) and nothing else; call sites only know the host.

## Compiled rules

Rules are TOML. They compile to function pointers on fixed context fields at
load time, so an event costs one pointer call and one linear wildcard match per
condition instead of entering the interpreter. First match wins; `allow` and
`deny` stop evaluation, `notice` lets it continue.

```toml
[[rule]]
name = "vip-exception"
hook = "command"
command = "PRIVMSG"
account = "operator"
action = "allow"

[[rule]]
name = "no-badword"
hook = "command"
command = "PRIVMSG"
text = "*badword*"
action = "deny"
notice = "That word is not welcome here"
```

Conditions: `command`, `nick`, `user`, `host`, `channel`, `text`, `account`.
All are wildcards (`*`, `?`), all must match, and `account = "-"` means "not
authenticated" while `account = "*"` means "any account". A rule file that
names an unknown hook, or a `deny`/`notice` rule without a notice, fails to
load: a typo must not silently disable a guard.

## Context argument

Every hook and scripted command receives one map:

| Key | Type | Meaning |
|---|---|---|
| `server` | string | Server name |
| `nick` | string | Sender nickname (empty before registration) |
| `user` | string | Username |
| `host` | string | Host shown to other clients |
| `command` | string | Command verb |
| `params` | array | Parameters in wire order |
| `channel` | string | Channel name when the command targets one, else empty |
| `text` | string | Trailing parameter, usually the message text |
| `oper` | bool | Sender is an IRC operator |
| `account` | string | SASL account, empty when not authenticated |

## Events

| Hook | When it runs | Veto meaning |
|---|---|---|
| `on_command` | Before any command is dispatched | The command is not executed |
| `on_connect` | After registration completes | Lines are delivered; cannot undo registration |
| `on_join` | After a successful `JOIN` | Lines are delivered |
| `on_part` | After a client leaves a channel | Lines are delivered |
| `on_privmsg` | On a channel or private message | Lines are delivered |
| `on_nick` | After a nickname change | Lines are delivered |
| `on_quit` | When a client disconnects | Lines are delivered; the user is gone |

## Return contract

* `()` — no opinion, continue.
* `true` / `false` — allow or veto. A veto wins over any later `true`.
* A string — send that raw line to the client.
* An array of strings — send each line.
* A map — `#{ allow: bool, notice: "text", lines: ["..."] }`.

## Scripted commands

Define `cmd_<name>` to add a command the server does not implement:

```rhai
fn cmd_hello(ctx) {
    "NOTICE " + ctx.nick + " :Hello from Rhai"
}

fn on_command(ctx) {
    if ctx.command == "PRIVMSG" && ctx.text.contains_text("badword") {
        return #{ allow: false, notice: "That word is not welcome here" };
    }
}
```

## Shared state and helpers

All scripts share one key/value store, which is how one script exposes helpers
to another:

```rhai
// scripts/state.rhai
fn on_join(ctx) {
    shared_set("last_join", ctx.nick);
}

// scripts/report.rhai
fn cmd_report(ctx) {
    "NOTICE " + ctx.nick + " :last join was " + shared_get("last_join")
}
```

Available natives: `shared_set(key, value)`, `shared_get(key)`, `shared_has(key)`,
`shared_remove(key)`, `log(level, message)`, `upper(s)`, `lower(s)`, `trim(s)`,
`contains_text(haystack, needle)`.

## Limits

The engine has no filesystem, network, or process APIs. A script that exceeds
`max_operations` is aborted and treated as having no opinion; the failure is
logged at `warn`. `eval` is disabled so scripts cannot compile code at runtime.
