# Running & Testing D-Voting

Every command here was run on a clean checkout before being written down.

**Requirements:** Node ≥ 22.18 and nothing else. No database, no Docker, no
external service.

```bash
npm install
npm run build:web     # bundles the crypto library for the browser
```

Server-side code runs straight from TypeScript with no build step. The one
exception is the browser bundle: a browser cannot run TypeScript, and ballot
encryption has to happen on the voter's device. It is built from the *same*
`@dvoting/crypto` the server and tests use, unminified so it can be diffed
against source, and the build refuses to ship if server-only key material ends
up in it.

---

## 1. Run the test suite

```bash
npm test              # 495 tests across six workspaces
```

Per package, if you want to narrow it down:

```bash
npm test --workspace @dvoting/crypto                  # 174 — the cryptography
npm test --workspace @dvoting/ledger                  #  90 — chain & consensus
npm test --workspace @dvoting/ballot-box              # 132 — lifecycle, voting, ceremony, portal, admin
npm test --workspace @dvoting/registration-authority  #  73 — roll, credentials, roll administration
npm test --workspace @dvoting/validator-node          #  16 — HTTP consensus
npm test --workspace @dvoting/trustee                 #  10 — what a trustee refuses to decrypt
```

Types and dependency audit:

```bash
npm run typecheck --workspaces
npm audit                                             # expect: 0 vulnerabilities
```

A single test file, when you are working on one thing:

```bash
node --test packages/crypto/test/benaloh.test.ts
```

**Reading the tests is the fastest way to understand the system.** Names state
the property, and the attack tests are written from the attacker's side:
`REJECTS a ballot stuffed with an inflated vote`, `CANNOT fork: two views at one
height cannot both reach quorum`, `catches the client when it lies about what it
encrypted`.

---

## 2. The narrated demo — start here

```bash
npm run demo          # ~20s
```

Runs a complete election in one process and narrates every step: registration
with blind-signed credentials, on-device ballot encryption, a malicious voting
app being caught by a cast-or-audit challenge, fraud attempts being refused,
block sealing, a coerced voter re-voting, public chain verification, a Merkle
inclusion proof, homomorphic tallying, threshold decryption, publishing a
recountable result — and finally tampering with the ledger to show detection.

```bash
node services/ballot-box/src/scripts/full-election-demo.ts 25 modp3072
```
runs it with 25 voters at full production security (slower).

Two narrower demos:

```bash
node packages/crypto/bench/demo-election.ts 25   # the cryptography alone
npm run bench                                    # performance numbers
```

---

## 3. Run a real election yourself (eleven processes)

```bash
npm run dev           # or: node scripts/dev-up.ts 20
```

This starts **four validator authorities, five trustees, the Registration
Authority and the ballot box, each as its own process**, generating every key and
a demo electoral roll. It prints every console URL and token.

**The election is deliberately not opened for you.** Composing the ballot,
freezing the roll and sealing it to the chain is the part that makes this an
election rather than a demonstration, so you do it.

> `dev-up` generates every party's keys in one place, which is exactly what a
> real deployment must never do. In production each authority — validator,
> trustee, RA — generates its own key on its own hardware and publishes only the
> public half. Everything it writes lands in `.local/` (gitignored).

### Step 1 — the commission opens the election

<http://localhost:8082/admin>, with the two printed tokens. They are separate on
purpose: one authorises the ballot box, the other the Registration Authority.
They are different authorities, and a single token would quietly merge them.

1. **The ballot.** One candidate or party per line.
2. **The roll.** Enrol voters — their enrolment codes are shown **once**, because
   the service stores only an HMAC. Then *freeze the roll*: that produces the
   digest which gets sealed onto the chain. Use *export* to publish the roll so
   anyone can recompute that digest and confirm it matches.
3. **Schedule** (optional). A closing time is enforced by the clock, not by an
   operator remembering to act.
4. **Open the poll.** This seals candidates, limits, schedule, roll commitment,
   trustee roster and validator set into block 0. None of it can change
   afterwards — try editing the ballot and watch the console refuse.

### Step 2 — voters vote

<http://localhost:8082/vote>, with any polling card. Dashes, spaces and case in
the enrolment code do not matter.

At step 3 the app shows a **ballot fingerprint** and offers *Cast* or *Check*.
Choosing *Check* runs a Benaloh cast-or-audit challenge: the app must reveal the
secret that unlocks the ballot, proving it encrypted what you picked. That
spoils the ballot, so you go back and prepare a fresh one — which is the point.
A dishonest app cannot know in advance which attempt you will check.

Everything happens in the browser: the candidate choice, the anonymous
credential, the blinding factor and the encryption randomness never leave the
tab, and none of them is written to storage.

**Verify a ballot** at <http://localhost:8082/verify> — paste a tracking code, or
follow the link straight from the receipt. Your browser re-derives the block
hash, re-checks each validator's Ed25519 signature, and re-walks the Merkle
path. Nothing the server says is trusted.

### Step 3 — the commission closes the poll

Back at `/admin`. Closing is irreversible and written to the chain, so it
survives a restart. The console then shows five trustees, all waiting, and says
plainly that there is nothing it can do to hurry them.

### Step 4 — the trustees unlock the count

Each trustee has **their own console on their own port**, with a token the
commission does not hold. Open any three of the five, connect, and press
*Verify and contribute my share*.

Each one lists what it established for itself before applying its share:

```
Re-verified 5 blocks against a 3-signature quorum
Confirmed this share matches trustee 2 in the sealed roster
Confirmed voting is closed on the chain
Recomputed all 4 encrypted totals from 3 counted ballots
```

That last line is the important one. The trustee does not trust the ballot box's
arithmetic — it downloads the board and adds the ballots up itself. If the ballot
box had inflated a total or dropped a ballot, the trustee stops and says so.

When the third share lands, the result seals itself onto the chain.

### Step 5 — anyone recounts it

<http://localhost:8082/results> shows the tally alongside an independent recount:
every ballot re-verified, the counted set re-derived, the homomorphic totals
recomputed, every trustee's decryption proof re-checked, and the announced
numbers recomputed from scratch.

Watch it from a voter's side too: while the ceremony is under way, `/results`
shows the public progress — which trustees have contributed and how many are
still needed.

### Try the command line instead

```bash
node services/registration/src/scripts/demo-voter.ts \
  http://localhost:8081 R-100001 <ENROLMENT-CODE>
```

Walks through fetching and *pinning* the issuer key, proving eligibility,
blinding a credential locally, getting it signed, unblinding, and verifying.

Ctrl+C stops everything.

---

## 4. Poke the API directly

```bash
# Public election parameters, and the issuer key a voter pins
curl localhost:8082/v1/election
curl localhost:8081/v1/issuer

# Bulletin board
curl localhost:8082/v1/bulletin/head
curl localhost:8082/v1/bulletin/blocks/0   # the sealed election configuration
curl localhost:8082/v1/bulletin/ballots/<tracking-code>
curl localhost:8082/v1/bulletin/verify      # full chain re-verification
curl localhost:8082/v1/bulletin/result      # 404 until a result is published

# The decryption ceremony, public to read
curl localhost:8082/v1/ceremony

# A validator authority
curl localhost:8090/v1/status
curl localhost:8090/v1/verify

# Admin (401 without the token)
curl -H "Authorization: Bearer $ADMIN_TOKEN" localhost:8082/v1/admin/status
curl -H "Authorization: Bearer $ROLL_TOKEN"  localhost:8081/v1/admin/roll
```

`GET /v1/bulletin/blocks/0` is worth reading in full: it is the whole election —
candidates, issuer key id, election public key, trustee roster, validator set,
quorum, schedule and the roll commitment. Everything a voter is shown can be
checked against it.

---

## 5. Deploying for real

The dev script exists so the system can be seen working. A real deployment
differs in ways that are the whole point:

| Local | Real |
|---|---|
| One script generates every key | Each authority generates its own, on its own hardware |
| Validators on one machine | One per organisation, over TLS (ideally mTLS) |
| Five trustees on one laptop | One per organisation, ideally opposed ones — a threshold of parties with the same interests is not a threshold |
| `STORAGE_DRIVER=memory` for the RA | Postgres — `npm run db:up`, then `npm run db:migrate --workspace @dvoting/registration-authority` |
| Roll seeded from a file | Enrolled through the console or `npm run roll:import --workspace @dvoting/registration-authority -- roll.txt`, cards printed and posted |
| Roll published nowhere | Exported and published, with an objection window, before the freeze |
| `modp2048` for speed | `modp3072` — the default in code |
| Trustee shares in `.local/` | One per trustee, on separate hardware |

Each service refuses to start in an unsafe production configuration: the ballot
box and validators require `CHAIN_PATH`, and the RA refuses in-memory storage
when `NODE_ENV=production`. The ballot box additionally refuses to start if its
configured issuer key, election key, validator set or quorum disagrees with the
election sealed on the chain — a mismatch means one of the two is wrong, and
there is no safe way to guess which.

---

## 6. What to look at

| Question | File |
|---|---|
| What an administrator can and cannot do | [docs/election-lifecycle-and-administration.md](docs/election-lifecycle-and-administration.md) |
| Why blind signatures, and why PSS | [docs/registration-and-blind-signatures.md](docs/registration-and-blind-signatures.md) |
| Ballot encryption, ZKPs, threshold decryption | [docs/ballot-encryption-and-tallying.md](docs/ballot-encryption-and-tallying.md) |
| What the blockchain is *actually* for | [docs/ledger-and-bulletin-board.md](docs/ledger-and-bulletin-board.md) |
| Defending against a malicious voting app | [docs/cast-as-intended.md](docs/cast-as-intended.md) |
| Removing the trusted dealer | [docs/threshold-key-generation.md](docs/threshold-key-generation.md) |

Every one of those ends with a **Known Limitations** section. Those are the most
useful pages to read before a viva — they are where the honest answers are.
