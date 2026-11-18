# Design: typed identifiers (`IssuerUrl`, `Audience`, `AuthorizedParty`)

Status: implemented in `0.3.0` across four commits. Where the implementation
differed from this proposal, the difference is recorded in §11.

Target release: `0.3.0` (pre-1.0, so a breaking change moves the minor number —
see `CHANGELOG.md`).

## 1. The problem

The crate parses three identifiers into `String` and passes the strings around.
The consequence is that a value's *origin* is not visible in its type, and the
same string is re-validated at every seam it crosses.

Issuer identifiers today:

| Site | What it does |
|---|---|
| `src/config.rs:220` | `Url::parse(&iss)` — discards the `Url` |
| `src/config.rs:239` | `Url::parse(&iss)` — discards the `Url` |
| `src/config.rs:318` | `Url::parse(&self.iss)` again, in `discovery_url` |
| `src/config.rs:671` | `Url::parse(&issuer.iss)` again, in `validate` |

So the parsed form is computed three times, thrown away twice, and the field
the constructors wrote is `pub`, so a caller can overwrite it with a value that
never parsed. `tests/config.rs:216-230` exists specifically to pin the
consequence: `validate` must re-derive the URL because it cannot trust the
field.

Audiences and authorised parties are `Vec<String>`. Nothing stops an audience
being compared against an `azp` list, and both gates do exactly that kind of
comparison today (`src/validator.rs:254`, `:302`).

## 2. Decisions taken

1. **The type parses once; `AuthConfig::validate` keeps the scheme policy.**
   `IssuerUrl` guarantees a well-formed absolute URL with no query and no
   fragment. Whether *cleartext* is tolerable stays in `validate`, because
   `allow_insecure_http` admits loopback stubs and the whole integration suite
   runs on `http://127.0.0.1`. The https rule does not move.
2. **Newtypes cover `Claims` too**, not only configuration.
3. **Soft breakage via `TryFrom`.** `Issuer::discover("https://…", ["myapp"])`
   keeps compiling. Reading values back changes shape.
4. **Delivered as staged commits** that each pass `cargo test`.

## 3. Two findings that shape the design

### 3.1 `Url` normalisation would silently break every Google deployment

`url` normalises a URL, so the parsed form is not the claim text:

```
https://accounts.google.com          -> https://accounts.google.com/      (added "/")
https://example.com                  -> https://example.com/
https://EXAMPLE.com/foo              -> https://example.com/foo          (lowercased)
https://sso.example.com/realms/demo  -> unchanged
```

`iss` is compared **byte-for-byte**. `src/claims.rs:121-124` says so, and
`tests/validation.rs:223-235` pins it: a trailing slash makes a different
issuer. If `IssuerUrl` were a transparent wrapper over `Url` and comparisons
used `as_str()`, then `Issuer::discover("https://accounts.google.com", …)` —
the first line of the README example — would store
`https://accounts.google.com/` and reject every real Google token, whose `iss`
carries no slash. `jsonwebtoken`'s own `set_issuer` gate
(`src/validator.rs:653-658`) would fail first, with `InvalidIssuer`.

**Therefore `IssuerUrl` keeps both forms:**

```rust
pub struct IssuerUrl {
    raw: String,   // exact claim text; every comparison and Display uses this
    url: Url,      // parsed; discovery derivation and scheme checks use this
}
```

Equality, hashing and ordering are `raw` only, matching the documented
semantic. The `Url` is derived state, so it takes no part in identity.

### 3.2 `jsonwebtoken` validates from its own parse, so `Claims` types cannot feed it

`jsonwebtoken::decode` deserialises the payload **twice**
(`decoding.rs:297-299`): once into `T` (our `Claims`) and once into its
private `ClaimsForValidation` (`validation.rs:183-194`), whose fields are
`TryParse<Issuer<'a>>` and `TryParse<Audience<'a>>`. `set_issuer` and
`set_audience` are matched against *that* struct.

Two consequences:

- Typing `Claims.iss` does **not** make the `jsonwebtoken` gates typed. The
  crate still passes plain `&str` to `set_issuer`, and that is fine.
- A strict `Deserialize` on `Claims.iss` would surface a malformed `iss` as a
  serde failure inside `decode`, which `src/validator.rs:507` renders as the
  generic `"failed validation"`. That would *lose* diagnostics.

**Resolution — parse `iss` once, before `decode`.** `claimed_issuer`
(`src/validator.rs:677`) already reads `iss` from the unverified payload to
select a trust bundle. It returns `Option<IssuerUrl>` instead of
`Option<String>`, and reports its own specific error when the claim is not a
URL. Because the same string is pre-parsed, `Claims`' strict `Deserialize`
cannot fail on it afterwards. Diagnostics improve rather than regress.

## 4. The newtypes

New private module `src/types.rs`, re-exported from `src/lib.rs` beside
`Issuer` and `AuthConfig`.

### 4.1 `IssuerUrl`

```rust
/// The exact `iss` value of a trusted issuer, with its parsed form.
///
/// Guarantees, established at construction and never re-checked:
/// - non-empty
/// - parses as an absolute URL (a scheme is present)
/// - carries no query and no fragment
///
/// The scheme is *not* constrained here. Whether cleartext is tolerable is a
/// deployment-wide decision that `AuthConfig::validate` makes once.
pub struct IssuerUrl {
    raw: String,
    url: Url,
}

impl IssuerUrl {
    pub fn parse(iss: &str) -> Result<Self, AuthError>;

    /// The exact claim text. This is what `iss` is compared against.
    pub fn as_str(&self) -> &str;

    /// The parsed form, for deriving `<iss>/.well-known/openid-configuration`
    /// and for the scheme check in `AuthConfig::validate`.
    pub fn url(&self) -> &Url;

    /// RFC 8414 §3.1 discovery location, with the issuer's path preserved.
    pub(crate) fn discovery_url(&self) -> Url;
}

impl fmt::Display for IssuerUrl   // writes `raw`
impl PartialEq / Eq / Hash        // on `raw` only
impl TryFrom<&str>  / TryFrom<String> / TryFrom<&String>  // Error = AuthError
```

Notes:

- `discovery_url` becomes infallible: the string already parsed at
  construction, so the `Result` and its error branch disappear. Its body is
  moved from `src/config.rs:317-333` unchanged otherwise.
- `Url::parse` rejects a scheme-less string with `RelativeUrlWithoutBase`, so
  the `keycloak.example/realms/demo` case is refused by the same call that
  establishes the type. `Issuer::new`'s separate `is_empty` guard folds in
  here, so the message `"issuer is empty"` survives with a single owner.

### 4.2 `Audience` and `AuthorizedParty`

Same shape, written as two explicit types rather than a macro, because their
doc comments carry different reasoning and that reasoning is the point of
having them.

```rust
pub struct Audience(String);
pub struct AuthorizedParty(String);

impl Audience {
    /// Refuse a blank entry. A blank audience can never match, so it is an
    /// outage disguised as a security control.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError>;
    pub fn as_str(&self) -> &str;
}
// AuthorizedParty mirrors this.

impl Display / AsRef<str> / PartialEq / Eq / Hash
impl Serialize / Deserialize           // #[serde(transparent)]: wire shape unchanged
impl TryFrom<&str> / TryFrom<String>   // Error = AuthError
```

**The config constructor validates; the serde deserialiser does not.** That is
the one deliberate asymmetry:

- `Audience::new` is on the configuration path. The operator wrote the value,
  so a blank one is theirs to fix, and it is refused where it was written.
- `Deserialize` is on the token path. `Claims.aud` records what the issuer
  asserted. A blank entry there is untrusted input, and it is already refused
  by the audience gate, which names the offending value. Rejecting it during
  deserialisation would replace that message with a serde failure.

`AuthorizedParty` gets the same split for the same reason: `azp: ""` in a
configured list is an operator mistake, `azp: ""` in a token is an attacker's
input.

To keep comparisons readable in tests and in hosts, add:

```rust
impl PartialEq<str> for Audience    // and for AuthorizedParty
impl PartialEq<&str> for Audience
```

so `claims.aud[0] == "myapp"` compiles. This is an ergonomic addition, not a
trust decision, and nothing in the crate gates on it.

## 5. Public API diff

### Changed

| Item | Before | After |
|---|---|---|
| `Issuer::iss` | `pub iss: String` | removed; `pub fn iss(&self) -> &IssuerUrl` |
| `Issuer::discover` | `(impl Into<String>, impl IntoIterator<Item = impl Into<String>>)` | `(impl TryInto<IssuerUrl>, impl IntoIterator<Item = impl TryInto<Audience>>)` |
| `Issuer::with_jwks_url` | same as above | same as above, plus `jwks_url: Url` |
| `Issuer::authorized_party` | `(impl Into<String>)` | `(impl TryInto<AuthorizedParty>)` |
| `Issuer::audiences` | `&[String]` | `&[Audience]` |
| `Issuer::authorized_parties` | `&[String]` | `&[AuthorizedParty]` |
| `AuthConfig::all_audiences` | `Vec<String>` | `Vec<Audience>` |
| `AuthConfig::all_authorized_parties` | `Vec<String>` | `Vec<AuthorizedParty>` |
| `Authenticator::issuers` | `impl Iterator<Item = &str>` | `impl Iterator<Item = &IssuerUrl>` |
| `Authenticator::all_audiences` | `&[String]` | `&[Audience]` |
| `Authenticator::issuer_audiences` | `(&self, iss: &str)` | `(&self, iss: &IssuerUrl)` |
| `Authenticator::all_authorized_parties` | `&[String]` | `&[AuthorizedParty]` |
| `Authenticator::issuer_authorized_parties` | `(&self, iss: &str)` | `(&self, iss: &IssuerUrl)` |
| `Claims::iss` | `String` | `IssuerUrl` |
| `Claims::aud` | `Vec<String>` | `Vec<Audience>` |
| `Claims::azp` | `Option<String>` | `Option<AuthorizedParty>` |

### Unchanged

- `AuthConfig::issuers: Vec<Issuer>` stays public and mutable. Every field of
  `Issuer` it could reach is now typed or private, so mutation can no longer
  introduce an unparsed issuer.
- `Issuer::jwks_url: Option<Url>` stays public.
- `Issuer::discovery_url` stays `pub(crate)`, but loses its `Result`.
- Wire shape of `Claims` is byte-identical thanks to `#[serde(transparent)]`.
- `Authenticator::authenticate(&self, token: &str) -> Result<Claims, AuthError>`.

### Migration for a caller

```rust
// Still compiles: the argument position accepts &str via TryFrom.
Issuer::discover("https://accounts.google.com", ["myapp"])?
    .authorized_party("myapp-client");

// Reads change shape.
for audience in issuer.audiences() {
    println!("{}", audience.as_str());   // was: &String
}
let exact = issuer.iss().as_str();       // was: `issuer.iss`

// No longer compiles, by design: the field cannot be written.
// cfg.issuers[0].iss = "identity.example".to_owned();
```

## 6. Internal seams

| Item | Before | After |
|---|---|---|
| `jwks::IssuerSlot.iss` | `String` | `IssuerUrl` |
| `JwksRegistry::new` | `(impl IntoIterator<Item = (String, Url)>, …)` | `(impl IntoIterator<Item = (IssuerUrl, Url)>, …)` |
| `JwksRegistry.slots` | `HashMap<String, IssuerSlot>` | `HashMap<IssuerUrl, IssuerSlot>` |
| `JwksRegistry::key_for` | `(&self, iss: &str, …)` | `(&self, iss: &IssuerUrl, …)` |
| `JwksRegistry::issuers` | `impl Iterator<Item = &str>` | `impl Iterator<Item = &IssuerUrl>` |
| `Inner.issuer_audiences` | `HashMap<String, Vec<String>>` | `HashMap<IssuerUrl, Vec<Audience>>` |
| `Inner.issuer_authorized_parties` | `HashMap<String, Vec<String>>` | `HashMap<IssuerUrl, Vec<AuthorizedParty>>` |
| `Inner.audiences_for_reporting` | `Vec<String>` | `Vec<Audience>` |
| `claimed_issuer` | `Option<String>` | `Option<IssuerUrl>` |
| `aud_hint` | `&[String]` | `&[Audience]` |
| `union_of` | `&'a String` | generic over `T: Clone + PartialEq` |

The `HashMap` keys become `IssuerUrl`, which hashes on `raw`. Lookup is then a
`&IssuerUrl` borrow with no allocation, where the current code clones the
issuer string into every map at boot (`src/validator.rs:127`, `:165`, `:170`).

## 7. What `AuthConfig::validate` loses

Four guards become unconstructible and are deleted, not kept as decoration:

| Guard | Why it can go |
|---|---|
| `issuer.iss.is_empty()` (`config.rs:659`) | `IssuerUrl::parse` refuses empty |
| `Url::parse(&issuer.iss)` arm (`config.rs:671-679`) | the field *is* the parsed URL |
| blank audience (`config.rs:717-722`) | `Audience::new` refuses blank |
| blank `azp` (`config.rs:723-730`) | `AuthorizedParty::new` refuses blank |

Two guards stay, and the reason must be restated because the old one cites a
route that no longer exists:

- **No issuers configured**, **no algorithms**, **leeway**, **timeout**,
  **`min_fetch_gap`**: unaffected.
- **Duplicate issuer** (`config.rs:662-665`): still reachable, since
  `with_issuer` can be called twice. Compares `&IssuerUrl` now.
- **Empty audience set** (`config.rs:701-716`): still reachable from an
  in-crate struct literal (`audiences: Vec::new()`), which is the only shape
  the private field leaves open. **Backstop retained.**
- **Cleartext scheme** (`cleartext_problem`): retained verbatim, now reading
  `issuer.iss().url()` instead of re-parsing.

The six doc comments that currently justify a guard by citing "the literals
this module's tests build" need rewriting as part of Stage 1, because the
set of such literals shrinks.

## 8. Test and example impact

171 sites in `tests/` and `examples/` read `.iss`, `.aud`, `.azp`, `.issuers`,
`all_audiences`, `issuer_audiences`, `all_authorized_parties`, or
`issuer_authorized_parties`. There are four `Claims` literals built from JSON
(`tests/claims.rs:27`, `src/validator.rs:1137`, `:1198`) — these keep working
because `Deserialize` is transparent.

Three tests change meaning rather than shape, and each needs a deliberate
rewrite rather than a mechanical one:

1. `tests/config.rs:216-230`
   `validate_still_rechecks_an_issuer_mutated_after_construction` — the premise
   is gone: the field cannot be written. Replace with a test asserting the
   accessor returns the value the constructor accepted, and that no setter
   exists.
2. `tests/config.rs:426-435` `an_issuer_configured_with_an_empty_audience_is_refused`
   — the refusal moves from `validate` to `Audience::new`, so
   `Issuer::discover(URL, [""]).expect("valid issuer")` no longer succeeds.
   Rewrite as an `expect_err` on the constructor, asserting the same wording.
3. `tests/config.rs:438-470` `validate_reports_every_problem_at_once` — two of
   its four expected problems (blank audience, blank `azp`) are now reported
   before `validate` runs. Rewrite with four problems `validate` still owns
   (no issuers, no algorithms, leeway, timeout, `min_fetch_gap`, cleartext).
   The "report everything at once" property it protects is preserved.

`tests/common/mod.rs` gains a couple of helpers (`Audience`/`AuthorizedParty`
constructors) so the other 168 sites stay one-line diffs.

## 9. Staging

Each stage compiles, passes `cargo test`, and passes `cargo clippy` with the
workspace lint levels.

| Stage | Content | Expected touch |
|---|---|---|
| 1 | `src/types.rs` with `IssuerUrl` only; `Issuer`, `validate`, `discovery_url`, `Claims.iss`, `claimed_issuer`, `jwks` slots, `Inner` keys, tests | ~20 files |
| 2 | `Audience`; `Claims.aud`, `Issuer::audiences`, `all_audiences`, `issuer_audiences`, `aud_hint`, `union_of` | ~10 files |
| 3 | `AuthorizedParty`; `Claims.azp`, `Issuer::authorized_parties`, the `azp` gate | ~8 files |
| 4 | `README.md`, `examples/`, `CHANGELOG.md` `0.3.0` entry with a Migration section, and a pass over the doc comments that cite the removed routes | ~5 files |

Stage 1 is the only one that changes behaviour in a way a reviewer must
scrutinise (the `claimed_issuer` pre-parse). It is also the only one where a
`Url` normalisation mistake is silently catastrophic, which is why §3.1 is
pinned by a dedicated test in that stage:

```rust
#[test]
fn a_host_with_no_path_keeps_the_claim_text_it_was_given() {
    let iss = IssuerUrl::parse("https://accounts.google.com").expect("a URL");
    assert_eq!(iss.as_str(), "https://accounts.google.com");
    assert_eq!(iss.url().as_str(), "https://accounts.google.com/");
    assert_ne!(iss, IssuerUrl::parse("https://accounts.google.com/").unwrap());
}
```

## 10. Risks accepted

- **Breaking on return types.** `audiences()` returns `&[Audience]`, so a host
  that formatted the old `&String` breaks. Chosen over a silent
  `Deref<Target = str>`, which would have hidden the change and made the
  newtype escape into arbitrary string APIs.
- **`TryInto` inference.** `Issuer::discover(url, [])` where the item type is
  not yet pinned may need a turbofish. `Vec::<Audience>::new()` at
  `src/config.rs:932` already shows the pattern.
- **`PartialEq<str>` is convenience, not proof.** A host can still compare an
  audience to a hard-coded string. The type's guarantee is that config values
  are non-blank and separated by role, not that a comparison is correct.
- **`IssuerUrl` holds two copies of the issuer.** Roughly 40 bytes extra per
  issuer, at boot only.

## 11. What the implementation changed from this plan

Four things were found while building it, and each is recorded here because a
proposal that quietly diverged from the code is worse than no proposal.

1. **`Audience::from_wire` was added; `AuthorizedParty` did not need one.**
   §4.2 said the wire shape is taken as it arrives. `Claims::aud` is built by a
   custom deserialiser that reads raw `String`s, so it needed a crate-internal
   constructor without the blank check. `Claims::azp` is an
   `Option<AuthorizedParty>`, which goes through the macro's already-lenient
   `Deserialize`, so a second constructor would have been dead code.
2. **`Debug` does not delegate to `Display` for `Audience` and
   `AuthorizedParty`.** The first attempt did, and
   `tests/observability.rs` caught it: the TRACE line carrying `aud` changed
   from `["my-audience"]` to `[my-audience]`. `lib.rs` documents that log line,
   so `Debug` now quotes exactly as `String` did. `IssuerUrl`'s `Debug` **does**
   delegate to `Display`, because showing both of its internal forms invites a
   reader to compare them and conclude they disagree about the issuer.
3. **A `string_identifier!` macro holds the mechanical impls.** §4.2 proposed
   writing the two types out explicitly. The struct, its documentation, and its
   validating constructor are still hand-written per type — that is where the
   reasoning lives — but `Display`, equality, hashing, the serde impls and the
   `TryFrom` conversions are generated, so two copies cannot drift.
4. **`PartialEq<String>` was added to the macro.** §4.2 listed `PartialEq<str>`
   and `PartialEq<&str>` only. `Vec`'s `PartialEq` delegates to its elements, so
   without this an assertion like `claims.aud == vec!["my-api".to_owned()]`
   stops compiling. It is the same convenience the other two impls are, and
   nothing gates on it.

Two smaller notes:

- `Issuer::authorized_party` returning `Result` is the single place a **valid**
  caller must add a character, as §5 predicted. `lib.rs`, `README.md`, and
  `examples/quickstart.rs` all needed the `?`.
- `SECURITY.md` still listed `0.1.x` as the supported line, which was already
  stale at `0.2.0`. It now names `0.3.x`, so the security policy and the release
  do not contradict each other.
