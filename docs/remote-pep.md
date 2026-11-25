# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether a signed-in person (a validated `SamlLogin`) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; this library builds it from your configuration, turns its SAML 2.0 sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is `Permit`, `Deny` or `Unavailable`, and `Unavailable` (no policy held yet, iya-sts unreachable, or a panic while deciding, which the PEP catches and notes) must be treated as a refusal. Every PEP failure is a refusal: `decision.http_status()` is 200 for a Permit and 403 for a Deny and for `Unavailable` alike, never a 5xx a client might retry into a different answer. Whether the person is signed in at all (401) is your application's question, asked before the PEP's.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Cargo feature | `pep` | `local` |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is `Unavailable`, and the Permit cache (if on) is emptied | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes give the same answer for the same request: `local` maps the request through the realm's catalogue exactly as iya-sts does, and its engine is held to iya-sts's conformance corpus.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it.

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the service provider in iya-sts as usual; `scripts/configure_iya_sts.py` does it for the demo. Note its identifier: it is the `application` the PEP is bound to (`entityId` by default).

For the demo, `scripts/configure_iya_sts.py --pep local` (a bare `--pep` is `local` too) or `--pep central` does this step and steps 2 to 6 in one run; see *The demo* below.

### 2. Create the PEP's service account

The PEP signs in as a service account of its own, never as a person or as the application:

```bash
api users/create '{"username":"pep-orders","invent":false,
  "credential":"none","serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"pep-orders","displayName":"pep-orders"}}'
api groups/add-member '{"group":"remote-peps","member":"pep-orders"}'
```

Console: **Users → New user** (tick **Service account**), then the `remote-peps` group's **Add member**.

### 3. Make the PEP's key, certify it and bind the PEP

Generate the key where the application runs. Only the certificate request leaves the machine:

```bash
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out pep-key.pem
openssl req -new -key pep-key.pem -subj /CN=pep-orders -out pep-key.csr
api xacml/issue-pep-credential "$(jq -n --rawfile csr pep-key.csr \
  '{name: "pep-orders", csr: $csr, application: "<application id>"}')"
```

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own**: this library refuses a configuration where it is `privateKey` (the key that signs requests, decrypts assertions and authenticates the receiver).

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or with `POST /admin-api/xacml/authzen/set-attribute`. For example, to make `acr` available as `urn:example:acr`:

```bash
api xacml/authzen/set-attribute '{"object":"subject","property":"acr","attributeId":"urn:example:acr"}'
```

which is the row

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to `resource.properties`, `action.properties` and `context` members you put on an `Access`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`; anything else comes through the catalogue rows of step 4, or from iya-sts's PIP for attributes on the person's directory entry. The resource's type arrives as `urn:sts:xacml:authzen:resource-type`.

For an application that enforces no fine-grained authorization, a root that permits `read` on an `order` when the person's `acr` arrived, and denies everything else, can be written in ALFA (the console's **Policies** tab does the same):

```bash
api xacml/import-alfa "$(jq -n --arg alfa '
namespace orders {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute rtype { category = resourceCat
        id = "urn:sts:xacml:authzen:resource-type" type = string }
    attribute acr { category = subjectCat id = "urn:example:acr" type = string }
    policy ordersRoot {
        id = "urn:example:orders"
        apply firstApplicable
        rule readOrder {
            permit
            target clause act == "read"
            target clause rtype == "order"
            condition integerGreaterThan(stringBagSize(acr), 0)
        }
        rule otherwise { deny }
    }
}' '{name: "orders", alfa: $alfa}')"
api xacml/set-root '{"name":"orders"}'
```

Every change to that policy, or to which policy is the root, is sent to a `local` PEP as `pep-policies-changed` (step 6).

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll, and the application's page in the console warns about it.

## Build with the feature

```toml
saml2-sp = { version = "…", features = ["pep"] }    # central
saml2-sp = { version = "…", features = ["local"] }  # local (includes central)
```

Without the feature a `pep` section is refused when the configuration is read, rather than silently ignored. A section that names no `mode` is `local`, so a build with `pep` alone must name `"mode": "central"`; otherwise it is refused the same way.

## Configure

Add a `pep` section to `saml.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `local` | `local` (the PEP pulls its application's policies, caches them in memory and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM: a path; a relative one is read from the configuration file's directory, like `privateKey`. The file is re-read when it changes. |
| `pdpUrl` | the identity provider's entityID. iya-sts's SAML entityID is the realm's issuer, so this is the service's URL with the realm prefix | iya-sts, with `/realm/<id>` for a realm. |
| `application` | `entityId` | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | on when this library's receiver runs (an `ssf` block, and `signals` not `false`) | Whether a signal stream hands over policy-change events. Without one, `local` polls at `pollIntervalMs`. |
| `pollIntervalMs` | 15000 | `local` without a signal stream. |
| `fallbackPollMs` | 300000 | `local` with one, in case an event is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. The policy-change event clears it, and so does a failed evaluation or a failed heartbeat: no cached Permit is served until iya-sts answers an evaluation again, so an outage does not keep a Permit alive. |
| `supportedObligations` | `[]` | The obligation types your application discharges (see *Obligations*). |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | `idpCa` | PEM trust anchors for iya-sts's TLS. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused, so a misspelt one doesn't quietly fall back to a default. `ServiceProvider::create` and `from_file` start the PEP, after the identity provider's metadata is read (the `pdpUrl` default needs its entityID).

## Decide

```rust
use saml2_sp::ServiceProvider;
use saml2_sp::pep::{Access, Decision};

let sp = ServiceProvider::from_file("saml.json", None, None)?; // registers the PEP and, in local mode, pulls

// After the assertion validated into `login` and you tracked the session:
let access = Access::new("read", "order", order_id);
let decision = sp.decide_session(&receiver.session_index(), &local_id, &login, &access);
let status = decision.http_status(); // 200 for a Permit, 403 for anything else
match decision {
    Decision::Permit { obligations, .. } => serve(obligations),
    Decision::Deny { why } => forbidden(status, &why),          // 403
    Decision::Unavailable { why } => forbidden(status, &why),   // 403: fail closed
}
// Without a receiver: sp.decide(&login, &access)
```

`http_status()` is the rule rather than a convention: answer with it and a Deny, a decision that couldn't be made and a panic inside the PEP are all 403. The demo's two protected pages take their status from it.

`Access::new(action, resource_type, resource_id)` carries the AuthZEN action and resource. Add `resource_properties`, `action_properties` or `context` members as your policy needs them, each declared in the catalogue (step 4). The PEP always sets `context.application` to the bound application, whatever you put there.

**The subject** comes from the sign-in, never from a request header:

- **id:** the username: the first of `username`, `preferred_username`, `urn:oid:0.9.2342.19200300.100.1.1`, `uid` and `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` the assertion carries (iya-sts sends the username under the last three), else the NameID. iya-sts's PIP resolves a username, a DN or a certificate subject; a transient NameID names nobody it can resolve. `SamlLogin::username()` answers the same.
- **properties:** the attributes (by Name, and by FriendlyName), `AuthnContextClassRef` as `acr`, an `amr` attribute as `amr`, and `AuthnInstant` as `auth_time` in epoch seconds.

Only the properties the catalogue declares are sent.

**Ended sessions.** `sp.decide_session(&sessions, local_id, &login, &access)` checks the receiver's session index first. A session that isn't tracked any more (signed out, expired, or ended by `session-revoked` or another ending event) is a Deny, and iya-sts isn't asked.

**Without a `pep` section**, every decision is `Unavailable`.

### Obligations

A `Permit` can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny, so an obligation is never silently dropped. `advice` (local mode) can be ignored.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache, the PEP wants to hear when the policies change. Give the receiver the PEP in `ReceiverOptions::pep`.

```rust
let receiver = SignalsReceiver::new(ReceiverOptions {
    transmitter: transmitter_url,
    pep: sp.pep().cloned(),
    ..ReceiverOptions::default()
})?;
```

The receiver then asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed`, verifies each SET like every other one, and hands the event to the PEP. A stream that already exists (made before the `pep` section was added, or while the PEP was `central`) is updated with `PATCH` to ask for the event too; if the transmitter refuses, the receiver still starts, the refusal goes to the receiver's logger (`ReceiverOptions::log`, at `error`), and the PEP's heartbeat reports the event as `excluded`. The event is only a hint: the PEP pulls with its own credential and never trusts the event's contents. An event naming another PEP is ignored. The receiver also tells the PEP how its stream is doing: what the stream carries (`requested` or `excluded`) at start and after each good poll, and `down` after a failed poll and on `stop()`, so a `local` PEP polls its own policies while it cannot hear.

The receiver also tells the transmitter whose events it wants. A transmitter may carry only events about subjects it was told of, and iya-sts carries on an application's stream only events about people with an active session at that application. So each `track` (every sign-in) sends Add Subject for the person's `iss_sub` and `email` identifiers, and the end of the last local session for that person (`untrack`, or an event that ends it) sends Remove Subject, both from the poll thread before the next poll and never retried; a refusal (403 is the expected race) goes to the logger and `SignalsReceiver::subject_error()` and never fails a sign-in. `"ssf": {"addSubjects": false}` (`ReceiverOptions::add_subjects`) turns it off; a transmitter without `add_subject_endpoint` gets nothing.

## Operate it

- **Health.** `pep().unwrap().status()` reports whether the PEP is registered and running, whether it holds a policy (and which sync token), its decision counters and its current problems. It holds no secret, so it's safe on a health page.
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs** with its kind (`embedded`), application, mode, protocol version and whether its stream carries policy-change events. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential` (add `revokePrevious: true` to retire the old one), replace the file, and call `pep().unwrap().reload_key()` (or wait up to 30 s). The tokens bound to the old key are dropped.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts (`authzen.remote.decision`). In `central` mode iya-sts records its own.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision `Unavailable`, `status().registered` false, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| `Unavailable` and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| `Unavailable` with "no policy is held yet" (`local`) | The first pull hasn't succeeded. Check `status().last_error`: a 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| `Deny` saying the evaluation was refused (`local`: "refused (STS-AUTHZEN-0004)"; `central`: "the service refused the evaluation: invalid_request …") | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| `Deny` although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a Permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream doesn't carry the event: check the console's *policy-change events* column, `ssfAllowedEvents` (step 6), and the receiver's logger (`ReceiverOptions::log`, at `error`) for a refused stream update. |
| The configuration is refused for the assertion key | It is one of this library's own keys. The PEP needs a key of its own. |

## Testing central against local

Both modes must give the same answer to the same question. This library holds itself to that with its own case table, `src/authzen/cases.json`: the catalogue rows and policies it needs, and 45 cases, each a SAML sign-in, an `Access` and the answer your application would see. They cover Permit, Deny and NotApplicable; a missing claim and an undeclared one (dropped); undeclared resource, nested and context members and wrong-typed values (refused, so a Deny); integer, double, boolean and dateTime values, bags and dotted paths; a `context.application` naming another application; a directory attribute from iya-sts's PIP; obligations declared and not; an ended session (`decide_session`); a processing error (Unavailable); and an application that enforces fine-grained authorization, whose policy references another.

- `docker build --target test .` runs the cases through a `local` PEP against a stub PDP serving the table.
- `IYA_STS_IMAGE=<an iya-sts image> python3 scripts/live_authzen.py` (or `IYA_STS_URL` for a running one) provisions a fresh iya-sts as the steps above describe, with two PEPs, one per mode, and asks every case of both. It fails on any case where central and local differ, or either differs from the table, and prints each one. Its ports are `LIVE_STS_PORT` (18518) and `LIVE_DEMO_PORT` (18618, which only names the SP).

The live run found two differences, both about an application that enforces fine-grained authorization, and both are fixed: central now decides a rule in a policy the application's policy references (iya-sts resolves the application policy's references as it does for a `local` PEP's pull), and local now adds the two facts iya-sts adds for an application's policy (`urn:sts:xacml:fga:application` and `urn:sts:xacml:fga:stage`, for an application the catalogue pull lists in `fgaApplications`). Against an iya-sts with those fixes and iya-pep `c0d61ca`, all 45 cases give the same answer in both modes and the table's answer.

## The demo

Built with `local` (the Dockerfile does), the demo protects `GET /orders/<id>` with the PEP when `demo/saml.json` has a `pep` section (`read`; any other method is `write`, which the demo's policy denies): 401 without a sign-in, then the decision's `http_status()`: 200 on a Permit, and 403 on a Deny and on `Unavailable` (any PEP failure is a 403: the page says whether the PEP denied it or could not decide). With no service provider to ask (the configuration doesn't load) it is 403 too.

`GET /attribute-protected` is decided by the PEP too (`Access::new("read", "attribute-protected", "attr1")`): 200 when the person's directory attribute `attr1` is `abc123`, which the PEP asks iya-sts's PIP for (`urn:sts:xacml:attribute:attr1`; the assertion does not carry it), and 403 otherwise.

One command sets the demo up with its PEP: the install script with `--pep local` (or a bare `--pep`, local being the default) or `--pep central` (and `--pep-name`, default `pep-saml-demo`). After registering the service provider it does steps 2 to 6: the service account in `remote-peps`; a P-256 key made with `openssl` in `demo/generated/pep-key.pem` (0600, never printed, never in the image), certified and bound to the demo's application; the catalogue row `subject.acr` (`AuthnContextClassRef`, as `urn:example:acr`); the test user's `attr1=abc123` (it defines the realm's custom attribute `attr1` with a token minted with `admin:read admin:security` for that call alone, and says what a Security Administrator adds on the console only when the value cannot be set); and the demo application's own policy, which it enforces, permitting `read` on an `order` when the sign-in carried an `AuthnContextClassRef` and `read` on `attribute-protected` when `attr1` is `abc123`, and denying everything else. A run writes the current version over the script's own policy (its PolicyId) and leaves a policy under any other PolicyId alone. The realm root is never touched. It then writes the `pep` section (`name`, `mode`, `assertionKey: generated/pep-key.pem`) into `demo/saml.json`, keeping the other members. The Shared Signals stream that carries `pep-policies-changed` is authenticated by the TLS client certificate the realm issues the application (`ssf.clientCertificate` / `ssf.clientKey`, `demo/generated/ssf-client.*`), not the SAML key pair, and the PEP's own key is a third, separate key. `--dry-run` lists every call.

```sh
docker compose build
docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/demo:/app/demo" -e ADMIN_API_CLIENT_SECRET -e IYA_STS_URL \
  saml2-sp-rust-demo python3 scripts/configure_iya_sts.py --pep local
docker compose up --build
```

**Its tests.** `docker build --target test .` drives the demo's own router to both pages with a `local` PEP holding the demo's policy (`src/authzen/demo-orders.xml`, the XACML iya-sts stores for the install script's ALFA) and a stub iya-sts whose PIP answers `attr1` per person: 200 on both for `attr1=abc123` with an AuthnContextClassRef; 403 on `/attribute-protected` for another value or none; 403 for `POST /orders/42`; 403 on `/orders/42` for a sign-in without an AuthnContextClassRef; 401 signed out; 403 when the PEP cannot decide; each status also compared with `http_status()`. `python3 scripts/live_iya_sts.py --pep` checks the two pages against a fresh iya-sts in both modes, for the test user and for a second user given `attr1=not-abc123` (200 and 403 on `/attribute-protected`). `python3 scripts/live_ui.py` does it in a real headless browser (Playwright's image, in Docker): sign in through iya-sts's page, the POST binding, both pages by address and by the top bar's links (200 and 200), Sign out, Sign in with another account as the second user (403 on `/attribute-protected`, 200 on `GET /orders/42`, 403 on `POST /orders/42`), with screenshots.

Run it again against the same iya-sts to switch the mode: the account and the key are kept, and so is a policy an administrator wrote, and the PEP is bound again. Against a new iya-sts the kept key is certified there. `GET /live-status` shows the PEP's `status()` under `pep`. The image copies `demo/saml.json` in when it is built, so rebuild after the script writes the section (`docker compose up --build`); Compose mounts `demo/generated` read-only, which holds the PEP's key.

The signed-in page has three tabs: **Session**, **CAEP & RISC events** and **Policy enforcement** (`/?tab=pep`), the last showing the embedded PEP's `status()` as four collapsible panes (Decisions, Cached policy, The PEP, Control plane) and a **Try it** pane linking `/orders/42` and `/attribute-protected`, redrawn every 2 s by `demo/public/pep.js` from `GET /pep-status.html`, which keeps a pane you closed closed; `GET /pep-status` is the same as JSON. Both need a sign-in and carry nothing secret. Without a `pep` section the tab says there is no embedded PEP.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-rust#readme): the crate's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
