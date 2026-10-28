# Server link protocol

Listeners with `server_link = true` accept peer servers. The protocol is
RFC 2813-shaped, multi-hop on a spanning tree, and uses the same line format as
the client protocol.

## Handshake

```text
C: PASS <link-password>
C: SERVER <peer-name> 1 <peer-sid> :<peer description>
S: :<our-name> SERVER <our-name> 1 <our-sid> :<our description>
```

The password comes from the environment variable named by
`server.link_password_env`. If that variable is unset, links are refused. When
`server.peers` is non-empty, the announced name must appear in it. A second path
to a server that is already reachable is refused with `ERROR :Server is already
connected`, which keeps the topology a tree.

## Connecting out

`[[links]]` entries make the daemon dial the peer itself:

```toml
[[links]]
name = "hub.example.org"
address = "hub.example.org"
port = 7000
retry_initial_secs = 5
retry_max_secs = 300
```

The dialling side sends the same opening an inbound peer would:

```text
C: PASS <link-password>
C: SERVER <our-name> 1 <our-sid> :<our description>
S: :<peer-name> SERVER <peer-name> 1 <peer-sid> :<peer description>
```

Because the password arrived on the socket, the accepting side needs no special
case; it replies with its own `SERVER` and bursts. A dialled link skips the
`PASS`-before-`SERVER` check and instead requires the announced name to match a
configured entry, which stops a redirected connect from attaching an unconfigured
server. Everything after the opening is shared with inbound links.

`tls = true` verifies the peer certificate against the certificates in
`tls_ca_path`, checking it against `tls_server_name` (default: `name`). A
self-signed link certificate is therefore pinned by installing it as the
authority, with no public CA involved.

Link entries are read at startup: adding or changing a `[[links]]` entry needs a
restart, because each entry owns a long-lived retry task. After a successful
handshake the dialler leaves the peer alone while the route exists. When the link drops it retries from `retry_initial_secs`, doubling to
`retry_max_secs`, with 20% jitter so a hub restart does not make every peer
reconnect in the same instant. A link that had been established restarts from
the shortest delay, so a flapping peer recovers quickly while a dead one backs
off.

## Routing

Every server learns the rest of the network from introductions:

```text
:<origin-server> SERVER <name> <hops> <sid> :<description>
```

`hops` is the distance from the sender to the announced server. A receiver adds
one, keeps the route only if it is closer than the one it already has, and
forwards it only when the route changed. That makes convergence one pass per
topology change and makes loops impossible, because a worse path is never
forwarded. Introductions beyond 16 hops are dropped.

```rust
server.route("delta.test")      // -> ServerInfo { hops, link, sid, .. }
server.routes()                 // -> every remote server, nearest first
server.route_message(name, ..)  // -> send to the link that reaches `name`
```

`LINKS` reports the table, including hop counts.

A link that completes its handshake is also announced to the remaining links as
`SERVER <name> 1 <sid> :<description>`. Without that, a server one hop further
out would only ever learn the route from a later burst, so a third server
joining through the middle of a chain would stay invisible to its far end.

## User introduction

Remote users become shadow clients, so `NAMES`, `WHO`, `WHOIS` and channel
state treat them exactly like local users.

```text
:<nick>!<user>@<host> NICK <nick> <hops> <ts> <user> <host> <server> <modes> :<realname>
```

* `hops` increments at every server that forwards the introduction.
* `ts` is the creation timestamp (Unix seconds) of the user on its home server.
  It never changes for the life of the connection.
* `server` must already be in the routing table; introductions for unknown
  servers are dropped rather than leaving unreachable users behind.
* `modes` carries `i` and `w`; operator status is never propagated from a link.

Changing an existing nickname omits the trailing fields:

```text
:<old>!<user>@<host> NICK <new>
```

### Accounts

A user's SASL account follows the introduction as its own message, which keeps
the positional `NICK` form readable by peers that do not implement the
extension:

```text
:<nick>!<user>@<host> ACCOUNT <account>
```

It is sent for authenticated users only, immediately after their `NICK`, and is
repeated after a nick change. The message must come from the server that owns
the user; a receiver applies it to the shadow and forwards it to its other
links, so every server converges in one pass. `*` clears the account; `LOGOUT`
on the owning server produces exactly that message, so a logout is visible
everywhere as soon as it happens.

Because the account is part of the user's state, `+R` channels and `$a:` ban
entries evaluate remote users by their real account rather than treating them
as unauthenticated. A login that happens after registration is relayed with the
same message, so the account does not have to be present at introduction time.

## Collision resolution

When an introduction names a nickname that already exists, the two records are
compared by `(ts, server name)`:

1. The lower timestamp wins. An older user keeps the name.
2. Equal timestamps break on the lexicographically lower server name, so every
   server reaches the same verdict with no extra round trip.
3. The loser is removed with `KILL` and the winner is introduced.

The server that detects the collision either kills the local shadow it holds and
accepts the newcomer, or sends `KILL` back along the link the newcomer arrived
on. `KILL` propagates to every other link, so a server that still has its own
copy removes it too. A local client that loses receives
`ERROR :Closing link: Killed (Nick collision on <nick> (TS a vs b))`.

Renaming into an occupied nickname follows the same comparison: the older user
keeps the name and the younger one is killed.

## Events

```text
:<nick>!<user>@<host> JOIN <channel>
:<nick>!<user>@<host> PART <channel> :<reason>
:<nick>!<user>@<host> QUIT :<reason>
:<nick>!<user>@<host> PRIVMSG <target> :<text>
:<nick>!<user>@<host> NOTICE <target> :<text>
:<nick>!<user>@<host> TOPIC <channel> :<topic>
:<nick>!<user>@<host> MODE <channel> +<flags>
:<server> INVITE <nick> <channel>
:<server> KICK <channel> <nick> :<reason>
:<server> KILL <nick> :<reason>
:<server> SQUIT <server> :<reason>
PING <token>
PONG <token>
ERROR :<reason>
```

State changes are relayed to every other link, so a three-server chain converges
in one pass. Private messages take the route to the recipient's server and are
delivered to that link only. Channel messages are delivered to local members and
relayed once; a message is never sent back to the link it arrived on.

## Join enforcement

A joining server checks its own copy of the channel before it announces the
join, but the two copies can disagree: the channel may be full, keyed,
invite-only, account-only or carry a ban the joining server never learned
about. A receiving server therefore re-checks every remote join against its own
state, using the account carried in the user's introduction and the key carried
on the join itself.

`JOIN <channel>{,<channel>} [<key>{,<key>}]` pairs keys with channels by
position, exactly as a client sends them. The receiving server never echoes the
key to channel members, but it does forward it with the join so the next hop can
apply the same `+k` check rather than trusting the previous server. `INVITE` is
relayed the same way: each server records the invitation against its own handle
for the invitee, which is what lets a remote user pass `+i`.

A refusal is not dropped silently — the user has already been told they
joined — so it travels back along the arriving link as
`KICK <channel> <nick> :<reason>`. The user's home server removes the
membership, tells the client and forwards the `KICK`, so every server agrees
that the user is out. An ordinary `KICK` from a remote operator, including one
aimed at a local client, travels the same path.

## Netburst

A link that completes its handshake immediately receives the accepting
server's complete state, because a peer reconnecting after a split starts from
an empty view:

```text
:<our-name> SERVER <name> <hops> <sid> :<description>     one per server behind another link
:<nick>!<user>@<host> NICK <nick> <hops> <ts> <user> <host> <home> <modes> :<realname>
:<nick>!<user>@<host> ACCOUNT <account>                   only for logged-in users
:<our-name> SJOIN <channel> <ts> <modes> [args] :<members>
:<our-name> TOPIC <channel> :<topic>
:<our-name> MODE <channel> +<b|e> <mask>
:<our-name> INVITE <nick> <channel>                        one per outstanding invitation
:<our-name> EOB
```

* `NICK` is sent for every user the server knows, with `<hops>` set to the
distance of the user's home server and `<home>` naming it. A server that
reconnects to a hub in the middle of a chain therefore learns the users two
hops away, whose home server is not the one it linked to. Repeats are
harmless: the receiver sees the same `(ts, home server)` and refreshes.
* `SJOIN` carries the channel creation timestamp, the channel modes with their
  arguments (key, limit) and every member with its `@`/`+` prefix.
* A logged-in user is followed by `ACCOUNT`, so authentication survives the
  reconnect exactly like membership and channel modes do.
* `TOPIC` and list `MODE` lines belong to the `SJOIN` of their channel. Modes
  and lists merge per entry (see below); the topic is owned by the copy with the
  lower `TS`, so a stale peer cannot overwrite a newer topic.
* Topics, ban/exception lists and invitations follow their channel, since a
  burst is ordered per channel.
* `INVITE` replays the invitations still outstanding for that channel, so a
  user invited before the split can pass `+i` afterwards. The line carries the
  server prefix, which marks it as state rather than a live invitation: the
  receiver records it and forwards it, but does not notify the invitee again.
  Invitations for users who left with the split are gone, since an invitation
  is a grant to a session, not to a nickname, and only invitations that have not
  exceeded `server.invite_expiry_secs` are replayed.
* `EOB` closes the burst. Nothing before it has to be applied in order, but the
  receiving server uses it to know the exchange is complete.

Applying a burst is idempotent: a user with the same `(ts, home server)` is
refreshed instead of being treated as a collision, and membership is only ever
added.

Channel modes merge mode by mode, so a split does not throw away the changes
made on either side:

* Boolean modes (`i`, `m`, `n`, `p`, `s`, `t`, `R`) are unioned: a mode set on
  either side survives. A mode cleared on one side is restored by the other
  side's copy, because the wire format carries no per-mode timestamp that could
  say which change came later.
* `k` and `l` hold one argument each, so the older channel (lower `TS`) keeps
  its argument. At equal `TS` the lexicographically smaller key and the
  numerically lower limit win, which gives both servers the same verdict
  without an extra round trip.
* Ban and exception lists are unioned by mask, since each entry stands alone.
* The topic has a single owner: the copy with the lower `TS`. An equal-`TS`
  burst leaves the local topic alone.

Burst messages are forwarded to the other links like any other event, so a
single burst reaches servers that were not directly connected to the sender. A
`TOPIC` or `MODE` from a burst names the originating server, which the next hop
would reject because it only accepts its direct peer as a server prefix, so a
forwarding server re-signs the relayed copy with its own name. The stored topic
setter and ban `set_by` keep the original server.

## Partitions

A link that closes is treated as a partition. The server:

1. removes every route reached through that link (its whole subtree),
2. removes every shadow user whose home server was in that subtree, broadcasting
   `QUIT` to local channel members,
3. sends `SQUIT <server> :<reason>` for each lost server to the remaining links.

`SQUIT` about a server further away removes that server and its users and is
forwarded on. `SQUIT` about a direct peer tears down the link and therefore
prunes everything behind it. Messages addressed to a server that is no longer
routable are dropped rather than flooded, so a split network does not deliver
into the void.

A split heals when either side redials: the new link is followed by a netburst,
so the reconnecting server does not have to relearn the network from
introductions. If neither side has a `[[links]]` entry for the other, the link
stays down until an operator restores it.

## Not implemented

* Redundant links and split-mode healing. The topology must be a tree; a second
  path is refused rather than kept as a backup.
* Replaying removals across a split. The merge is additive, so a mode or a ban
  cleared on one side is restored by the other side's copy, and divergence in
  membership is only corrected by later `QUIT`/`KICK`/`KILL` events.
* TS6 UID/SID addressing. The wire form is RFC 2813-shaped with TS fields, not
  byte-compatible with TS6.
* Link TLS client-certificate authentication. Use a TLS listener plus the shared
  secret, and firewall the port.

## Ban propagation

Network-wide bans travel as their own message so a peer never has to interpret
a channel list to find them:

```
:<server> BAN <kind> <set_at> <expires> <set_by> <mask> :<reason>
:<server> UNBAN <kind> <mask>
```

`kind` is one of `K`, `G`, `Z` or `S`; `expires` is an absolute Unix instant, or
empty for a permanent entry. A receiver refuses a `BAN` whose prefix is not the
peer that sent it, ignores a `K` (local policy is not shared), stores the rest
and forwards it to its other links. Applying a burst is idempotent: the same
kind and mask replaces the entry rather than duplicating it.

The netburst sends every active global ban before `EOB`, so a server that
reconnects after a split refuses exactly what the rest of the network refuses.

## Global operator notices

```
:<mask> GLOBOPS :<text>
```

Each server delivers the notice to its own operators and forwards it to the
other links; the origin is excluded so a tree delivers it once per operator.
