# RFC compliance

Scope: RFC 1459, RFC 2810, RFC 2811, RFC 2812 and RFC 2813.

> **Note on RFC 7184.** RFC 7184 is "Definition of Managed Objects for the
> Optimized Link State Routing Protocol version 2 (OLSRv2)" and has nothing to
> do with IRC. The IRC-related RFC from that period is RFC 7194, which records
> the convention of serving TLS on port 6697; this server implements that
> convention on its TLS listeners.

## RFC 1459 / RFC 2812 — client protocol

### Connection registration

| Command / numeric | State | Notes |
|---|---|---|
| `PASS` | Implemented | Password comes from `server.password_env`; plaintext compare of the supplied secret |
| `NICK` | Implemented | RFC 1459 nickname grammar, configurable length, case-only renames allowed |
| `USER` | Implemented | Username validated, real name truncated at 200 chars |
| `QUIT` | Implemented | Broadcast to common channels before teardown |
| `PING` / `PONG` | Implemented | Server ping timeout enforced by the connection driver |
| `ERROR` | Implemented (outbound) | Sent on kill, shutdown and protocol violations |
| `001`–`005` | Implemented | `005` carries `CASEMAPPING`, `CHANTYPES`, `CHANMODES`, `PREFIX`, `NETWORK`, limits |
| `251`–`255`, `265`, `266` | Implemented | |

### Channel operations

| Command | State | Notes |
|---|---|---|
| `JOIN` | Implemented | Keys, `+i`, `+k`, `+l`, `+R`, ban and exception checks; multiple channels per command |
| `PART` | Implemented | Empty channels are reclaimed |
| `MODE` | Implemented | Channel: `i m n p s t R k l o v b e`; user: `i w o` |
| `TOPIC` | Implemented | `+t` enforcement, `332`/`333` replies |
| `NAMES` | Implemented | Multi-prefix aware, replies split to respect the 512-byte line limit |
| `LIST` | Implemented | Secret/private channels hidden from non-members |
| `INVITE` | Implemented | Invitations consumed on join, on the invitee's quit, or after `server.invite_expiry_secs`; both parties are notified before and at expiry |
| `KICK` | Implemented | Multiple targets per command |

### Messaging and queries

| Command | State | Notes |
|---|---|---|
| `PRIVMSG` / `NOTICE` | Implemented | `+n`, `+m`, bans, away replies, multiple targets, `echo-message` |
| `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN`, `INFO`, `LINKS` | Implemented | |
| `WHO` | Implemented | Channel and mask forms, invisible users filtered |
| `WHOIS` | Implemented | Includes channels, idle/signon, oper flag, away |
| `WHOWAS` | Implemented | Bounded ring buffer (`limits.whowas_size`) |
| `AWAY` | Implemented | `away-notify` push to capable members |
| `ISON`, `USERHOST` | Implemented | |
| `OPER`, `KILL`, `REHASH`, `WALLOPS`, `STATS` | Implemented | Flag-gated, `STATS l`/`STATS u` only |
| `SQUIT`, `SERVER`, `CONNECT`, `DIE`, `RESTART` | Not implemented (client side) | Operator lifecycle commands are intentionally absent; `SERVER`/`SQUIT` exist on links |

### Numerics not sent

`RPL_TRACE*`, `RPL_STATS*` beyond `l`/`u`, `RPL_USERHOST` variants, `ERR_TOOMANYTARGETS`
(the target list is truncated instead), and the `RPL_USERS*` family are unused.

## RFC 2810 — architecture

Single server by default; multiple servers can be linked. Clients are isolated:
one handle per socket, a bounded outbound queue, and no shared mutable session
state across await points. Message ordering per client is preserved by reading
and dispatching sequentially for that connection.

## RFC 2811 — channel management

Supported channel modes: `i` invite-only, `m` moderated, `n` no external
messages, `p` private, `s` secret, `t` topic lock, `R` authenticated users only,
`k` key, `l` limit, `o` operator, `v` voice, `b` ban, `e` ban exception.
Prefixes `@` and `+`, `CHANMODES=b,e,k,l,imnpstR`, `MAXLIST=b:100,e:100`.
Channel operators are granted to the first joiner, as RFC 2811 describes.

`+e` exceptions are checked before `+b` bans, so a matching user is never
banned. Entries written as `$a:<pattern>` match the SASL account name
(case-insensitively, wildcards allowed) instead of `nick!user@host`, so an
account ban follows the user across nick and host changes; `$a:*` matches every
authenticated user. `+R` refuses joins (`477`) and messages (`404`) from
unauthenticated users. A member who joined before `+R` was set keeps their
membership but must authenticate before speaking.

These rules are enforced on joins arriving over a link as well, together with
`+i`, `+k` and `+l`. A receiving server re-checks a remote join against its own
copy of the channel, judging the user by the account carried in their
introduction and by the key carried on the join, and returns a refusal as a
`KICK` so the user's home server removes the membership and tells the client.
`+R`, `+i`, `+k`, `+l` and `$a:` therefore behave the same for local and remote
users, and a `$a:` ban written on any server holds across the network.
`INVITE` is relayed so each server records the invitation for its own handle of
the invitee, and a netburst replays the invitations still outstanding for each
channel, so `+i` keeps working across a reconnect. An invitation lapses when the
invitee disconnects or after `server.invite_expiry_secs`, and only unexpired
ones are replayed. A sweep every five seconds warns both the invitee and the
inviter `server.invite_warning_secs` before expiry and notifies them when it
lapses; each server notifies only the participants it houses locally, so a
remote party is told by its own server.

Not implemented: `+a` anonymous channels (obsolete), forwarding (`+f`).

## RFC 2813 — server protocol

Implemented on listeners marked `server_link = true`:

* `PASS` then `SERVER` handshake, with a shared secret from
  `server.link_password_env` and an optional peer-name allowlist.
* User introduction, `NICK`, `ACCOUNT`, `JOIN` (with its key), `PART`,
  `INVITE`, `KICK`, `QUIT`, `PRIVMSG`, `NOTICE`, `TOPIC`, channel `MODE`,
  `PING`/`PONG`, `ERROR`, `SQUIT`.
* Remote users are represented as shadow clients, so `NAMES`, `WHO`, `WHOIS`
  and message routing treat them uniformly.

* Multi-hop routing: a shortest-path table built from `SERVER` introductions,
  route-directed private messages, and `SQUIT`/`KILL` propagation across the
  tree. Hop counts increase at every hop and worse paths are never forwarded.
* Timestamp collision resolution: the lower TS wins, equal timestamps break on
  the lexicographically lower server name, and the loser is removed with `KILL`
  so every server converges on the same user.
* A lost link prunes its whole subtree, removes the users that lived there and
  tells the remaining peers which servers disappeared.
* Netburst: every accepted link is followed by `SERVER`, `NICK`, `SJOIN`,
  `TOPIC`, `MODE`, `INVITE` and `EOB`, and applying one is idempotent. A burst
  carries every user the server knows, not only its own, so a server that
  reconnects to the middle of a chain still learns the users two hops away. A
  link that comes up is announced to the remaining links, and a forwarding
  server re-signs relayed burst `TOPIC`/`MODE` lines with its own name. Modes
  merge per mode (booleans unioned, `+k`/`+l` from the older copy, lists
  unioned by mask); the older channel owns the topic.
* Account propagation: an `ACCOUNT` message follows every user introduction and
  every netburst entry, and post-registration logins are relayed, so `+R` and
  `$a:` bans evaluate remote users by their real account. Only the server that
  owns a user may set its account.
* Outbound dialling: `[[links]]` entries dial the peer themselves, sending the
  opening `PASS`/`SERVER`, and retry with jittered exponential backoff until the
  route is back, so a dropped link recovers without operator action. TLS links
  verify the peer against the certificates in `tls_ca_path`.

Gaps, stated plainly:

* The topology must be a tree. A second path to an already-known server is
  refused, so there is no redundant-link fallback or split-mode healing.
* Users are addressed by nickname rather than TS6 UID/SID. The wire form is
  RFC 2813-shaped with a TS field, not byte-compatible with TS6.
* Bursts are additive. When two sides have diverged on membership the merge
  keeps both sets until a `QUIT`/`KILL` arrives; there is no authoritative
  reconciliation pass.
* Link traffic is not encrypted unless the listener sets `tls = true`, and link
  client certificates are not supported.

## IRCv3 capabilities advertised

`multi-prefix`, `away-notify`, `server-time`, `extended-join`,
`userhost-in-names`, `cap-notify`, `echo-message`, `sasl`, `account-tag`,
`message-tags`, `labeled-response`.

`account-tag` attaches `@account=<name>` to `PRIVMSG`/`NOTICE` copies sent to a
client that negotiated it, including the `echo-message` copy, and to the `JOIN`,
`PART`, `QUIT` and `NICK` events of an authenticated user. Messages and events from an
unauthenticated user carry no tag, and events relayed from a linked server use
the account that server introduced, so the tag is consistent network-wide.

`message-tags` accepts client-only tags (`+name`) on `PRIVMSG` and `NOTICE`,
validates the key characters, caps the total at 4 KiB and relays them to
recipients that negotiated the capability, including across links. A tag without
the `+` prefix is dropped unless the operator lists it in
`server.client_tag_allowlist` (for example `example.com/foo`); `time`, `account`
and `label` are always server-owned and the configuration refuses to list them,
so a client cannot forge them. Server tags are added per recipient as usual.

`labeled-response` echoes the client's `label` tag on every reply to that
command, numerics and the command's own echo included, and answers a command
that produced no reply at all with `ACK`. The tag is honoured only after the
capability is negotiated, only tokens of unreserved characters (`A-Za-z0-9`,
`-`, `_`, `.`, `/`) up to 64 bytes are accepted, and the label is attached only
to the issuing client's deliveries, never to other recipients of a broadcast the
command caused.

Deliberately absent: `batch`, `chathistory`, `monitor`, `invite-notify`,
`chghost`, `setname`, `sts`.

## IRCv3 SASL

| Item | State | Notes |
|---|---|---|
| `AUTHENTICATE` before and after registration | Implemented | Re-authentication replaces the account |
| `PLAIN` | Implemented | `authzid NUL authcid NUL passwd`; the authzid must match the account when present |
| `EXTERNAL` | Implemented | TLS client certificate pinned by SHA-256 fingerprint; an optional authzid selects the account |
| 400-character chunking | Implemented | Reassembled up to 8 KiB, then rejected with `905` |
| `AUTHENTICATE *` abort | Implemented | `906`, in-progress state discarded |
| `LOGOUT` | Implemented | `901`; clears the account and sends `ACCOUNT *` to every link |
| `900` / `903` on success, `904` on failure, `908` for the mechanism list | Implemented | Failure reasons are not distinguished, by design |
| `sasl=...` capability value | Implemented | Lists only mechanisms an account can actually use |
| Mandatory authentication | Implemented | `sasl.require = true` withholds `001` until SASL succeeds |
| `SCRAM-*`, `OAUTHBEARER`, `ANONYMOUS` | Not implemented | `908` reports the supported set |

Account records come from an `ircd::auth::AccountBackend`. The built-in backend
reads `[[accounts]]` from the configuration; anything else (services package,
SQL, LDAP) plugs in through `Server::set_account_backend` without changes to the
protocol layer.

`EXTERNAL` does not validate a certificate chain. A chain would add nothing,
because the account pins one exact fingerprint; the handshake still proves the
client holds the matching private key through the `CertificateVerify`
signature. `tls.request_client_certs = true` makes the server ask for the
certificate.
