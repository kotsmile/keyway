# Rust rewrite rather than porting locker

keyway is the open-source successor to an internal Go service (`locker`), and it
is being written from scratch in Rust rather than lifted out of that repo. The
Go code is sound and tested, so the reason is not its quality: it depends on
internal shared packages (`oidcx`, `configx`) and on conventions owned by
another internal service (warden's role grammar, a hard-coded `/g:longyai`
group root in domain code), and untangling those is most of the work of a
rewrite without any of the freedom. Starting again also buys the one thing a
port cannot — the schema, the config vocabulary and the wire format are still
free to change, which is what makes ADR-0002 and ADR-0003 possible at all.

The upstream repo stays the reference for the domain model and for behaviour
worth keeping; `CONTEXT.md` is where that survived.
