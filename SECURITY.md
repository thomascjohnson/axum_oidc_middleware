# Security policy

`axum-oidc-middleware` decides whether an HTTP request may call your API. A
defect here is an authentication bypass. We therefore handle reports on a
separate track from ordinary bugs.

## Reporting a vulnerability

**Report privately. Do not open a public issue.**

Open a private vulnerability report on the
[security tab of the repository](https://github.com/thomascjohnson/axum_oidc_middleware/security/advisories/new).
Only maintainers see it. It can become a GitHub Security Advisory with a CVE
without ever becoming public. There is no security mailing list and no PGP key.
The private report is the channel.

If you cannot use GitHub, write to the address on the maintainer's crates.io
profile. Say in the subject line that the mail concerns a vulnerability.

Include these details:

- The exact version.
- The issuer configuration: `iss`, `aud`, `azp`, `algorithms`.
- A token or JWKS document that shows the behavior.

A failing test is better than a description.

### What counts as a vulnerability

Report any case where a caller with no credentials, or with weak ones, reaches
further than the verification order allows:

- The crate accepts a token it should reject. A cause may be algorithm
  confusion, a wrong or unverified `iss`, a missing or wrong `aud`, a key the
  attacker chose, or a `kid` collision.
- The JWKS trust bundle admits a key it should not. It may admit a symmetric
  key, an encryption key, or a key from a document the server did not serve
  over TLS.
- A request with only an invented `Authorization` header causes a panic, an
  unbounded allocation, or a task that never returns.
- A log line, an error response body, or a `Display` impl reveals a credential
  or signing material.

### What is out of scope

- **The documented limits.** These include HTTPS-only issuers, mandatory `kid`,
  no audience switch, `azp` as an opt-in narrowing, no revocation call, no
  introspection call, and no session or cookie handling. The docs
  [state them as deliberate](https://docs.rs/axum-oidc-middleware/latest/axum_oidc_middleware/#deliberate-limits).
  If you think one is exploitable and not merely limiting, report it anyway and
  say why.
- **Configuration you picked.** Examples: an `aud` that you share with another
  service, or an issuer that you administer. `allow_insecure_http` cannot reach
  past loopback. `validate` refuses a cleartext issuer on another host at boot.
  A report about that flag is therefore in scope only when the crate accepted
  the configuration.
- **The behavior of the issuer.** Examples: a realm that mints tokens for the
  wrong client, or a leaked issuer key.
- **Problems in dependencies.** `cargo audit` covers those already. Report them
  upstream.
- **Login flows that this crate does not implement.** This crate has no redirect,
  no session, and no cookie to attack.

## Supported versions

| Version    | Supported |
| ---------- | --------- |
| 0.1.x      | yes       |
| < 0.1      | no        |

Before 1.0, we fix only the latest release. When a fix ships, we yank the
older releases from crates.io instead of backporting to them. A verification path
that is half-patched is worse than a forced upgrade. The policy tightens at 1.0:
the current minor and the one before it stay supported.

## Timeline

- We answer within 7 days.
- We decide whether the report is a vulnerability, and we tell you, within 14
  days.
- We ship a patched release and a public advisory within 90 days of
  confirmation, or at public disclosure, whichever comes first.

We ship no fix for a report that turns out to show intended behavior. We send
the reasoning instead.

## Advisories

We publish advisories to the RustSec database, so `cargo audit` picks them up on
its own. The crates.io name fixes the path for this crate:

```text
crates/axum-oidc-middleware/RUSTSEC-YYYY-NNNN.md
```

A human-readable copy of each advisory sits at
`https://rustsec.org/advisories/RUSTSEC-YYYY-NNNN`. Here is the front matter,
written for this crate:

```toml
[advisory]
id = "RUSTSEC-0000-0000"
package = "axum-oidc-middleware"
date = "YYYY-MM-DD"
url = "https://github.com/thomascjohnson/axum_oidc_middleware/security/advisories/GHSA-xxxx-xxxx-xxxx"
# `categories` takes only the names in `rustsec::advisory::Category`:
# code-execution, crypto-failure, denial-of-service, file-disclosure,
# format-injection, malicious, memory-corruption, memory-exposure,
# privilege-escalation, thread-safety. Any other value parses as
# `Category::Other`, and advisory-db CI prefers a named one. An authentication
# bypass is `privilege-escalation`. A signature-verification flaw is
# `crypto-failure`. Put free text in `keywords`.
categories = ["privilege-escalation"]
keywords = ["authentication-bypass", "oidc", "jwt"]

[versions]
patched = [">= 0.1.1"]
unaffected = ["< 0.1.0"]
```

Work through these steps in order, so `cargo audit` and GitHub stay in sync:

1. Report the problem privately and confirm it, as above.
2. Publish a patched version to crates.io.
3. Publish a GitHub Security Advisory. That yields a CVE, and OSV and the GitHub
   Advisory Database then carry the entry.
4. Open a pull request that adds the advisory to
   [`rustsec/advisory-db`](https://github.com/RustSec/advisory-db/blob/main/EXAMPLE_ADVISORY.md)
   at the path above. RustSec wants the upstream report first, because its
   maintainers do not know the internals of this crate. CI in that repository
   enforces the front-matter rules.

There is no `Cargo.toml` key for any of this. The manifest has no security field.
RustSec keys advisories on the published crate name, not on anything inside the
`.crate`. This file is the declaration.

### Audit your own build

```console
$ cargo audit                       # RustSec
$ cargo deny check advisories       # RustSec, with your own policy in deny.toml
```

## Hardening on the caller side

None of the items below is a vulnerability. Each is a setting that makes a
guarantee real:

- Set `aud`, and keep that value private to this service. The crate never skips
  the audience test, so an `aud` that you share makes it meaningless.
- Name `algorithms` when your issuer uses a family other than RS256. Do not rely
  on the default.
- Keep `allow_insecure_http` off unless a stub issuer on loopback needs it. The
  crate refuses a cleartext issuer on any other host at boot. Treat this as a
  habit to keep, not as a control to rely on.
- Treat `TRACE` output like access-log material. It carries `sub`@`iss`, `aud`,
  and `exp`. It never carries the token.
