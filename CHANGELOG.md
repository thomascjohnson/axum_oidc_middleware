# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Being
pre-1.0, a breaking change moves the minor number: `0.1.x` to `0.2.0`.

## 0.2.0 - 2026-11-17

### Changed — audience and `azp` scope are now per issuer, and audience scope is
required

Both trust scopes moved from `AuthConfig` (one list for the whole deployment)
to `Issuer` (one list per issuer). A list beside the issuers was a default that
every issuer inherited, so a single flat audience list let any trusted issuer
vouch for any audience the deployment served.

- `Issuer::discover(iss)` is now `Issuer::discover(iss, audiences)`, and
  `Issuer::with_jwks_url(iss, jwks_url)` is now
  `Issuer::with_jwks_url(iss, jwks_url, audiences)`. The audience set is a
  required argument: an issuer that names no audience is a missing argument at
  the call site rather than a value that compiles.
- `AuthConfig::with_audience` is removed. There is no deployment-wide audience
  list to add to.
- `AuthConfig::with_authorized_parties` is removed. Use
  `Issuer::authorized_party` on the issuer those clients belong to.
- `Issuer::audience` is removed. Both constructors take the whole set
  (`Issuer::discover(iss, ["api", "billing"])`), so a builder that added one
  audience at a time was a second way to say the same thing.
- `Issuer::authorized_party` remains, as an additive builder on an issuer that
  already named its audiences.

Behaviour changes that follow from the above:

- An empty audience list is refused for **every** issuer, and at the
  constructor rather than at boot. It previously meant "the whole deployment
  list" for a lone issuer, and there is no deployment list to mean that now.
  Arity cannot see inside an iterator, so `Issuer::discover(iss, [])` still
  compiles — and returns an error, so an `Issuer` that exists always names at
  least one audience.
- An empty `azp` list turns that issuer's gate off **for that issuer alone**.
  A deployment that trusts a Keycloak realm and Google can gate the realm and
  leave Google ungated; Google never emits `azp`, and a gate it cannot satisfy
  is an outage. A single deployment-wide gate could not express this.
- A token's `azp` is checked against the list of the issuer that signed it.
  Client ids are unique within a realm, not across realms, so two trusted
  realms may each carry a client called `my-app` and a shared list admitted
  either one's token.

### Changed — readbacks are derived, and are not what the verifier enforces

- `AuthConfig::audiences()` is now `AuthConfig::all_audiences()` and returns
  `Vec<String>`: the union of the configured issuers' audiences in issuer order,
  deduplicated. It no longer returns a borrowed list, because there is no longer
  a list to borrow.
- `AuthConfig::issuer_audiences(&self, issuer)` is removed.
- `AuthConfig::authorized_parties()` is now
  `AuthConfig::all_authorized_parties()` and returns `Vec<String>`: the union of
  the per-issuer client lists, for reporting only. An entry in it is accepted
  only from the issuer that named it.
- `Authenticator::issuer_audiences(iss)` and
  `Authenticator::issuer_authorized_parties(iss)` are added. They return
  `Option<&[String]>` — `None` when no such issuer is configured, and an empty
  slice for an issuer whose `azp` gate is off.
- `Authenticator::audiences()` and `Authenticator::authorized_parties()` are now
  `all_audiences()` and `all_authorized_parties()`. Both return the union and are
  reporting only: no gate reads either. The `all_` prefix is the point — these
  union accessors were the last public shape that could be mistaken for the
  enforcement set, and that confusion is what this release exists to close.

### Changed — `Issuer` can no longer be built as a struct literal

`audiences` and `authorized_parties` are private. One private field is enough to
refuse a literal from another module, so a host that assembled an `Issuer` field
by field from its own config type must call a constructor instead. Those
constructors already ran the only URL parse, so nothing is newly unchecked.

`iss` and `jwks_url` remain public, and therefore mutable after construction.
`AuthConfig::validate` re-checks both, which is the last gate for that route.

### Migration

```rust
// Before
let config = AuthConfig::empty()
    .with_issuers([
        Issuer::discover("https://accounts.google.com")?,
        Issuer::discover("https://sso.example.com/realms/app")?,
    ])
    .with_audience("my-api")
    .with_authorized_parties(["my-client"]);

// After
let config = AuthConfig::empty().with_issuers([
    // Google emits no `azp`, so its client gate stays off — this issuer only.
    Issuer::discover("https://accounts.google.com", ["my-api"])?,
    // The client is named on the issuer whose realm defines it.
    Issuer::discover("https://sso.example.com/realms/app", ["my-api"])?
        .authorized_party("my-client"),
]);
```

A single-issuer deployment changes only where it states its audience: the same
list moves from `with_audience` to the issuer's own argument.
