# Operator tooling

Everything an IRC operator can do, what it costs, and what it deliberately does
not do.

## Privileges

`[[opers]]` grants a set of flags. `+o` on its own authorises nothing: every
command checks one bit in the session's privilege set, which was resolved when
`OPER` succeeded, so an authorisation decision is a masked comparison rather
than a search through the configuration.

| Flag | Grants |
| --- | --- |
| `kill` | `KILL` |
| `rehash` | `REHASH`, `BENCH` |
| `global` | `WALLOPS`, `GLOBOPS` |
| `die` | process shutdown |
| `admin` | `SAMODE`, channel override, joining restricted channels |
| `ban` | `KLINE`, `GLINE`, `ZLINE`, `SHUN`, `UNBAN` |

A configuration with an operator that has no flags is rejected: an entry that
grants nothing is a typo, not a policy. Duplicate operator names are rejected
for the same reason — the first match would silently win.

## Server notices and `SNOMASK`

`OPER` subscribes the new operator to every category and sets `+s`, because a
mode that advertises notices should not start out silent. `SNOMASK` edits the
subscription:

```
SNOMASK +bk        add categories
SNOMASK -g         remove one
SNOMASK            print the current mask
MODE <self> -s     stop receiving notices, keeping the subscription bits
MODE <self> +s     resume with the subscription unchanged
```

| Letter | Category |
| --- | --- |
| `c` | local client connections |
| `q` | local disconnects |
| `k` | kills and ban enforcement |
| `o` | operator authentication |
| `r` | configuration reloads |
| `l` | link establishment and netbursts |
| `b` | server bans added, lifted or triggered |
| `g` | `GLOBOPS` traffic |

Delivery is filtered per recipient at the notice site: one masked test and one
capability-free `NOTICE` per subscribed operator. An operator who is not
subscribed costs one boolean read.

## `GLOBOPS`

`GLOBOPS :text` sends `:nick!user@host GLOBOPS :text` to every local operator
and relays it to the other servers, each of which delivers it to its own
operators. In a tree this reaches the whole network exactly once per operator;
the relay excludes the link the message arrived on.

## `SAMODE` and override

`SAMODE <channel> <modes...>` runs the ordinary `MODE` parser and broadcasts
the ordinary `MODE` line, so peers apply it exactly as they would a change by a
channel operator. `SAMODE` on a nickname is refused: user modes are not forced
across the network.

An operator holding `admin` also bypasses the `JOIN` gate. The override is
checked inside the join path rather than in the command, so a relayed join
cannot take a different decision, and the channel operators receive a notice
naming the rule that was overridden (`+k`, `+i`, `+l`, `+R` or a ban).

`admin` is a blunt instrument: it does not let an operator read a channel's
history or see its member list without joining, and it does not bypass a
`QUIT`, `KILL` or a server ban.

## Server bans

| Command | Applies to | Propagated |
| --- | --- | --- |
| `KLINE <mask> <duration> :reason` | this server | no |
| `GLINE <mask> <duration> :reason` | the network | yes |
| `ZLINE <mask> <duration> :reason` | the network, by address | yes |
| `SHUN <mask> <duration> :reason` | the network, speech only | yes |
| `UNBAN <kind> <mask>` | lifts one entry | for global kinds |

Durations are `30`, `30s`, `5m`, `2h`, `7d`, `1w`, or `0` for permanent. The
stored expiry is an absolute Unix instant, so a ban set on one server means the
same moment everywhere the burst reaches it.

Masks are wildcards over `nick!user@host`, `user@host`, host or nick; `$a:`
matches a SASL account. A `ZLINE` compares only the peer address and the host it
resolved to, so a client cannot evade it by resolving a name. `STATS k` lists
the active entries.

`KLINE`, `GLINE` and `ZLINE` are checked before the welcome is sent, so a
refused client never appears on the network. `SHUN` is checked at delivery: the
client stays connected and state changes (`JOIN`, `TOPIC`, `NICK`) still work,
but `PRIVMSG` and `NOTICE` are dropped without a reply.

The empty-list fast path is one length read per message; the benchmark is
`cargo bench --bench oper`.

### What a ban does not do

A `SHUN` is not a moderation tool that hides the client: it stops speech and
nothing else. A `KLINE` is not a firewall: it refuses the connection after the
handshake, so the socket and TLS handshake still cost what any other connection
costs. Address bans behind a shared proxy will take the proxy's other users with
them. None of these replace connection throttling, which this server does not
implements yet.

## Diagnostics

`STATS k` lists active bans, `STATS l` lists links, `STATS u` lists uptime.
`BENCH` measures parse, fold and serialise on the live server when
`diagnostics.benchmarks` is enabled.

## Measured cost

`cargo bench --bench oper`, release build, single-threaded:

| Benchmark | Median |
| --- | --- |
| `oper_ban/empty_fast_path` | 6.3 ns |
| `oper_ban/miss_32` | 4.6 us |
| `oper_ban/hit_last_32` | 5.1 us |
| `snomask/contains` | 0.32 ns |
| `snomask/from_letters` | 19 ns |
| `snomask/letters` | 12 ns |

The empty path is one length read, so a network with no bans pays nothing per
message. The 32-entry scan is the worst case and is proportional to the ban
list, not to the message; building the two match masks once per check rather
than once per entry halved it. `snomask/contains` is a masked comparison, which
is why notice filtering costs nothing measurable per recipient.
