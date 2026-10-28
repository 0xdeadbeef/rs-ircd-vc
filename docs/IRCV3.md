# IRCv3 capabilities

Twenty-one capabilities are advertised. Every one is implemented in this tree;
a capability is only listed in `CAP LS` when the server can actually honour it
(`sasl` needs an account backend, `sts` needs TLS material).

## The set

| Capability | What it does here |
| --- | --- |
| `account-notify` | `ACCOUNT <name>` / `ACCOUNT *` to common-channel peers on login and logout |
| `account-tag` | `@account` on messages from authenticated senders |
| `away-notify` | `AWAY` pushed when a peer changes state |
| `batch` | Server-originated `BATCH` groups, used by `draft/chathistory` |
| `cap-notify` | `CAP NEW`/`CAP DEL` when the set changes |
| `chghost` | `CHGHOST <user> <host>` with the old mask as prefix |
| `echo-message` | The sender receives its own `PRIVMSG`/`NOTICE` |
| `extended-join` | `JOIN` carries account and real name |
| `invite-notify` | Channel operators see `INVITE` as it happens |
| `labeled-response` | `label` echoed on the issuing client's replies, `ACK` when a command replies nothing |
| `message-tags` | Client tags with a 4 KiB budget; `TAGMSG` for bodyless messages |
| `monitor` | Server-side presence list, `730`/`731` pushes |
| `multi-prefix` | Every status prefix in `NAMES`/`WHO` |
| `sasl` | `PLAIN` and `EXTERNAL` through the pluggable account backend |
| `server-time` | `@time` on delivery |
| `setname` | Real-name changes after registration |
| `standard-replies` | `FAIL` alongside the numeric for the common refusals |
| `sts` | `sts=duration=...` policy, only when TLS is configured |
| `userhost-in-names` | `nick!user@host` in `NAMES` |
| `draft/multiline` | A client `BATCH` of lines arrives as one message |
| `draft/chathistory` | `CHATHISTORY` replay from the bounded in-memory store |

## Behaviour that is not obvious from the names

**`TAGMSG`** is a command, not a capability: it travels under `message-tags` and
is delivered only to recipients that negotiated it. A message with no client tag
is dropped, because the body is mandatory and the server never invents one.

**`monitor`** holds at most 100 nicknames per session (`734` when full). A push
costs one hash lookup per connected watcher, and only local clients with the
capability negotiated are considered. `MONITOR S` reports the current state,
`MONITOR L` lists the entries, `MONITOR C` clears the list.

**`draft/multiline`** accepts one open incoming batch per session, at most 32
lines or 4096 bytes. Lines are joined with `\n` and delivered as one `PRIVMSG`
carrying `draft/multiline-concat`. The line's `batch` tag must match the open
reference and the target was fixed when the batch opened, so a line cannot
retarget the message. Exceeding a limit drops the batch and returns `417`.

**`draft/chathistory`** replays only channels the requester is joined to;
anything else is `442`. `LATEST`, `BEFORE`, `AFTER`, `AROUND` and `BETWEEN` are
supported, timestamps are RFC 3339 or Unix seconds, and a query returns at most
100 entries. The store is bounded per channel by `server.history_size` (default
256, zero disables it), is **not** persisted, and is **not** shared between
linked servers: each server replays what it saw locally. A restart loses it.

**`sts`** is advertised only when `tls.cert_path` is configured and
`server.sts_duration_secs` is non-zero (default 30 days). `CAP REQ sts` is
refused otherwise, so a client is never asked to enforce a policy this server
cannot meet.

**`standard-replies`** is additive: the numeric is still sent, and a negotiated
client additionally receives `FAIL <command> <code> :<text>` for join refusals,
unknown commands, missing parameters and insufficient privileges. It is not a
replacement for the numeric, so a client that ignores it loses nothing.

## Verification

`tests/ircv3.rs` drives the wire protocol for the capability list, `MONITOR`
pushes, `SETNAME` gating, multiline joining and chathistory batching.
`tests/network.rs` covers `sasl`, `message-tags`, `account-tag`,
`labeled-response`, `server-time` and `extended-join`. `src/server/history.rs`
has unit tests for every query range and the trimming policy.
