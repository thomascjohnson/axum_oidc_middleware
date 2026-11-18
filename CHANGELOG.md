# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Being
pre-1.0, a breaking change moves the minor number: `0.1.x` to `0.2.0`.

## 0.3.0 - 2026-11-18

### Fixed — one guard `0.3.0` said it had removed was still in the file

`AuthConfig::validate` still carried a check for an issuer configured with a
blank audience, one statement below the comment that says that check is gone.
It could not fire: `Audience::new` refuses a blank entry, it is the only
constructor a caller can reach, and `Issuer::audiences` is private. The entry
above said the same thing. The check is removed, so the code, the comment, and
that 0.3.0 entry now agree. No configuration that was accepted is refused, and
none that was refused is accepted.

### Tests — back to every function executed

The typed identifiers added functions the suite never called: `IssuerUrl`'s
`Debug`, `Serialize`, and `Borrow<str>`, and the `AsRef<str>`, `Hash`,
`PartialEq<str>`, and `TryFrom<&String>` impls of `Audience` and
`AuthorizedParty`. Each now has a test that states the property it exists for —
that a map keyed by `IssuerUrl` answers the claim text a token carried, that a
`Claims` value re-serialises to that text and not to the normalised URL, that a
`&String` read out of a config file builds an audience. `claimed_issuer`'s
refusal of an `iss` that is not an absolute URL had no test at all, and it is
the one behaviour change of 0.3.0 a reviewer had to take on trust; it is asserted
through `authenticate`, including that the refused value stays out of the
refusal. 220 tests, 100% of functions executed.

### Changed — identifiers are typed, and the parse happens once

The three values this crate makes decisions on — the issuer, an audience, and an
authorised party — were `String`s. Two consequences followed. An issuer had to be
an absolute URL with no query or fragment, but that rule lived in
`AuthConfig::validate` and the string was re-parsed at four sites, two of which
threw the parsed `Url` away. And `iss` was a **public** `String` field, so a
caller could overwrite it with a value no constructor ever saw; a test existed to
pin that `validate` re-checked because it could not trust the field.

Three new types replace those strings. `IssuerUrl`, `Audience`, and
`AuthorizedParty` are all re-exported from the crate root:

- `IssuerUrl` carries the exact `iss` claim text **and** its parsed `Url`. Both
  are needed. `iss` is compared byte for byte, and a URL parser normalises:
  `https://accounts.google.com` parses to a form with a trailing slash. Identity
  is the claim text, so the normalised form is used only to derive the discovery
  location. Empty, scheme-less, and query-or-fragment forms are refused by
  `IssuerUrl::parse`. Whether cleartext is tolerable stays in `validate`, which
  is a deployment-wide decision and unchanged.
- `Audience` and `AuthorizedParty` are distinct types, not two `Vec<String>`.
  The `aud` and `azp` gates can no longer be handed each other's list.
- `Claims::iss`, `Claims::aud`, and `Claims::azp` are typed too. The JSON wire
  shape is unchanged, so a host that logs or forwards a `Claims` value sees no
  difference.

Because the invariants are in the types, `AuthConfig::validate` no longer checks
for an empty issuer, a scheme-less issuer, a blank audience, or a blank `azp`.
None of those values can be constructed, inside the crate or outside it, so the
checks were dead code wearing the look of a safeguard. `validate` still owns the
https/loopback policy, the duplicate-issuer scan, an empty audience *set*, the
algorithm set, leeway, and the cache policy timings.

### Changed — API surface

- `Issuer::iss` (a public `String` field) is removed. Use `Issuer::iss()`, which
  returns `&IssuerUrl`. There is no setter: `iss` is settled when the issuer is
  built.
- `Issuer::discover` and `Issuer::with_jwks_url` take
  `impl TryInto<IssuerUrl>` and `impl TryInto<Audience>`. A `&str` or `String`
  argument still works, so a call site with a valid issuer and audience is
  unchanged.
- `Issuer::authorized_party` now returns `Result<Issuer, AuthError>`, because a
  blank client id is refused rather than stored. **This is the one place a valid
  call site gains a character:** the builder chain now needs a `?`.
- `Issuer::audiences()` returns `&[Audience]`, and
  `Issuer::authorized_parties()` returns `&[AuthorizedParty]`.
- `AuthConfig::all_audiences()` returns `Vec<Audience>` and
  `AuthConfig::all_authorized_parties()` returns `Vec<AuthorizedParty>`.
- `Authenticator::issuers()` yields `&IssuerUrl` rather than `&str`.
  `Authenticator::all_audiences()` returns `&[Audience]`, and
  `Authenticator::all_authorized_parties()` returns `&[AuthorizedParty]`.
  `issuer_audiences` and `issuer_authorized_parties` take `&IssuerUrl`.
- `Claims::iss` is an `IssuerUrl`, `Claims::aud` is a `Vec<Audience>`, and
  `Claims::azp` is an `Option<AuthorizedParty>`.

`Issuer::discovery_url` became infallible internally: its input is a type that
cannot be a non-URL. The public signature did not change; the method is
`pub(crate)`.

### Migration

```rust
// Still compiles, because the argument positions accept `&str`.
let issuer = Issuer::discover("https://accounts.google.com", ["my-api"])?;

// One `?` is new, and only for the builder that names a client.
let issuer = Issuer::discover("https://sso.example.com/realms/app", ["my-api"])?
    .authorized_party("my-client")?;

// Reading values back changes shape.
let exact = issuer.iss().as_str();            // was `issuer.iss`
for audience in issuer.audiences() {
    println!("{}", audience.as_str());        // was `&String`
}

// No longer compiles, by design: the field cannot be written.
// issuer.iss = "identity.example".to_owned();
```

A blank audience or a blank `azp` that used to fail at boot now fails on the
line that writes it. Both messages say which setting is blank, so the fix is the
same; only the moment it is reported has moved.

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
