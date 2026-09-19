# D-Voting

A cryptographically secure, blockchain-audited e-voting system.

The security guarantees come from an **end-to-end verifiable (E2E-V) cryptographic
protocol** in the Helios tradition. The permissioned blockchain is an
**audit/tamper-evidence layer**, not the source of ballot secrecy or integrity.
That split is deliberate: MIT/Harvard research (Park, Specter, Narula, Rivest,
2021) shows that treating a blockchain as the security mechanism for voting
produces undetectable, nation-scale failure modes.

> **Status:** a whole election runs end to end from a browser — the commission
> composes and opens it, voters cast, the poll closes, and a threshold of
> independent trustees unlocks the count. See [Roadmap](#roadmap).

---

## The four parties, and what each one can see

The design is one idea repeated: **no party ever holds two pieces of knowledge
that would let it link a voter to a vote, or produce a result alone.**

| Party | Knows | Never knows | Can do alone |
|---|---|---|---|
| **Election commission** | who is on the roll, what the ballot says | how anyone voted, the result | open and close the poll |
| **Registration Authority** | which roll entry registered | the credential it signed, any ballot | issue one credential per voter |
| **Ballot box + validators** | every encrypted ballot | who cast it | record ballots, tamper-evidently |
| **Trustees (k of n)** | one key share each | who cast what | **nothing** — the count needs k of them |

```
polling card ──▶ electoral roll ──▶ blind-signed credential   (unlinkable to the voter)
                              │
                              ▼
              ballot encrypted ON DEVICE + ZK validity proofs
                              │
                              ▼
              ballot box: eligibility + validity, learning neither
                              │
                              ▼
              permissioned ledger (PoA, Merkle-committed, append-only)
                              │
                              ▼
              homomorphic tally  (no ballot is ever decrypted)
                              │
                              ▼
              k-of-n threshold decryption + decryption proofs
                              │
                              ▼
              result published on-chain with every decryption proof
                              │
                              ▼
              public verification: chain, inclusion proofs, full recount
```

- **[`packages/crypto`](packages/crypto/)** — the whole protocol, built on
  WebCrypto + native BigInt with **no third-party crypto dependencies**. Runs
  unchanged on Node, in the browser, and in React Native.
  - RSA blind signatures — **RFC 9474 (RSABSSA)**
  - Exponential ElGamal over **RFC 3526** prime-order groups
  - Disjunctive Chaum-Pedersen ballot-validity proofs (**strong Fiat-Shamir**)
  - **Pedersen DKG** — the election key is never assembled anywhere
  - Shamir threshold decryption with per-trustee proofs
  - **Benaloh cast-or-audit** challenge for cast-as-intended verification
- **[`packages/ledger`](packages/ledger/)** — permissioned hash-chained ledger:
  **RFC 6962** Merkle inclusion proofs, Ed25519 validators, Proof-of-Authority
  with a Byzantine supermajority quorum. Each validator is an **independent node
  holding only its own key**, with its own chain replica, that re-verifies every
  block and refuses to equivocate.
- **[`services/registration`](services/registration/)** — the Registration
  Authority: authenticates a voter against the built-in **electoral roll** and
  issues exactly one blind-signed credential per entry.
- **[`services/ballot-box`](services/ballot-box/)** — verifies credentials and
  ballot proofs, seals them onto the ledger, serves the public bulletin board,
  and tallies from the chain. Holds **no signing keys**.
- **[`services/trustee`](services/trustee/)** — one process per trustee, holding
  exactly **one** key share. Before applying it, a trustee downloads the bulletin
  board, re-verifies every block against the validator quorum, and recomputes the
  encrypted totals itself — and refuses if any of that disagrees with the ballot
  box. It can help decrypt the **totals** and has no route that decrypts a ballot.
- **[`services/validator`](services/validator/)** — one process per authority.
  Holds a single Ed25519 key, keeps its own chain replica, and independently
  re-validates every block (including re-verifying ballots) before attesting.
- **Web interface** — everything is done from the browser.
  - `/vote` — prove eligibility, choose, **encrypt the ballot in the browser**,
    run a cast-or-audit challenge, cast, and get a tracking code. The candidate
    choice, the credential, the blinding factor and the encryption randomness
    never leave the tab and are never written to storage.
  - `/verify` — paste a tracking code; **your own browser** re-derives the block
    hash, re-checks each validator's Ed25519 signature, and re-walks the Merkle
    path. Nothing the server says is trusted.
  - `/results` — the published tally with an independent recount, and while the
    count is under way, live public progress of the trustee ceremony.
  - `/admin` — the commission composes the ballot, manages and freezes the roll,
    sets the schedule, and opens and closes the poll.
  - each trustee's own console, on their own machine, on their own port.

### The election's life is on the chain

Opening the poll seals the election's whole definition into block 0 — candidates,
selection limits, schedule, issuer key id, election public key, trustee roster,
validator set and the **electoral roll commitment**. Closing writes a second
entry. Both are irreversible, and both are the reason the guarantees survive a
restart rather than living in a variable an operator can flip.

An administrator can therefore do everything a real commission does, and none of
it invisibly:

| Admin **can** | Admin **cannot** |
|---|---|
| Add voters, freeze and publish the roll | Learn who voted, or whether someone voted |
| Set candidates and selection limits | Change any of it once the poll is open |
| Schedule and open the poll | Reopen a closed election, even by restarting |
| Close the poll, seal blocks | Decrypt anything, or see a running total |

The last row is structural: the ballot box holds no trustee key shares and no
validator keys, so there is no code path from the console to a plaintext vote.

**Adding voters is the exception, and it is stated plainly rather than hidden:**
a fabricated roll entry produces a cryptographically perfect ballot, and no proof
in the protocol distinguishes it from a real one. That is the boundary of what
cryptography can do about eligibility. The answer is the same as a real
election's — the roll is frozen, hashed, committed to the chain and published, so
a name added afterwards changes the digest and cannot be hidden.

Design rationale and honest limitations:
**[election lifecycle & administration](docs/election-lifecycle-and-administration.md)** ·
**[registration & blind signatures](docs/registration-and-blind-signatures.md)** ·
**[ballot encryption & tallying](docs/ballot-encryption-and-tallying.md)** ·
**[ledger & bulletin board](docs/ledger-and-bulletin-board.md)** ·
**[cast-as-intended](docs/cast-as-intended.md)** ·
**[threshold key generation](docs/threshold-key-generation.md)**

---

## Quick start

Requires Node ≥ 22.18 (uses native TypeScript type-stripping — there is no build step).

Full instructions, all verified on a clean checkout, are in
**[RUNNING.md](RUNNING.md)**. The short version:

```bash
npm install
npm run build:web # bundle the crypto library for the browser
npm test          # 495 tests across six workspaces
npm run demo      # a complete election, narrated, in ~20s
npm run dev       # the real system: 11 processes + the web interface
```

`npm run dev` starts four validators, five trustees, the Registration Authority
and the ballot box — and deliberately leaves the election **unopened**, because
composing it, freezing the roll and sealing it to the chain is the part that
makes this an election rather than a demonstration. It prints every console URL
and token.

### Watch the whole system run — this is the viva demo

```bash
node services/ballot-box/src/scripts/full-election-demo.ts 12
```

Runs everything: registration with blind-signed credentials, on-device ballot
encryption, **a malicious voting app being caught by a cast-or-audit challenge**,
fraud attempts being refused, block sealing, a coerced voter re-voting, public
chain verification, a Merkle inclusion proof, homomorphic tallying, threshold
decryption — and finishes by tampering with the ledger and showing the tampering
is detected.

```bash
# The cryptographic protocol alone, narrated
node packages/crypto/bench/demo-election.ts 25

# Performance numbers
node packages/crypto/bench/election-bench.ts
```

### Run the Registration Authority

```bash
# 1. Generate an issuer key (the private key goes to stdout)
npm run registration:keygen > issuer.key.json

# 2. Configure
cp .env.example .env
#    set ISSUER_PRIVATE_KEY_JWK to the contents of issuer.key.json
#    set IDENTITY_PEPPER and REGISTRATION_TOKEN_SECRET to fresh random values:
#    node -e "console.log(crypto.randomBytes(32).toString('base64url'))"

# 3. Start Postgres and migrate (or set STORAGE_DRIVER=memory to skip)
npm run db:up
npm run db:migrate --workspace @dvoting/registration-authority

# 4. Import the electoral roll (one roll number per line) and print the cards
npm run roll:import --workspace @dvoting/registration-authority -- roll.txt

# 5. Run
npm run registration:dev
```

Step 4 writes `enrolment-cards.csv` containing every voter's secret. Print the
cards, deliver them out of band, then **destroy the file** — only the HMAC of
each code is stored, so a lost card must be re-issued rather than looked up.

### See the whole flow

With the service running:

```bash
node services/registration/src/scripts/demo-voter.ts
```

This walks through the voter's side step by step — fetching and **pinning** the
issuer key, registering, blinding a credential locally, getting it signed,
unblinding, and verifying. Run it twice with the same document number to watch
the double-issuance defence refuse the second attempt.

---

## API

**Registration Authority**

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe |
| `GET /v1/issuer` | Public issuer key + `keyId`. Public and cacheable **on purpose** — every voter must confirm they got the same key as everyone else |
| `POST /v1/register` | Polling card in, short-lived registration token out |
| `POST /v1/credential/issue` | Token + blinded message in, blind signature out |
| `POST /v1/admin/roll` | Enrol voters; returns their enrolment codes **once** |
| `POST /v1/admin/roll/freeze` | Freeze the roll and return the commitment to seal |
| `GET /v1/admin/roll/export` | The roll identifiers, for publication |

**Ballot box**

| Endpoint | Purpose |
|---|---|
| `GET /v1/election` | Public descriptor: phase, candidates, keys, trustees, roll commitment |
| `POST /v1/ballots` | Cast. `POST /v1/ballots/audit` spoils and publishes an audited one |
| `GET /v1/bulletin/*` | The board: head, blocks, inclusion proofs, chain verification, result |
| `GET /v1/ceremony` | Public: the encrypted totals and which trustees have contributed |
| `POST /v1/ceremony/shares` | A trustee's partial decryptions. **No token** — the proof is the authentication |
| `POST /v1/admin/election/open` | Seal the election and open the poll. `…/close` ends it |

---

## Performance

Measured at 3072-bit, 4 candidates. Ballot casting runs on the voter's device,
so its cost is a usability constraint, not a vanity metric.

| Operation | Time | Notes |
|---|---|---|
| `createBallot` | **485 ms** | on the voter's phone |
| `verifyBallot` | **730 ms** | per observer, per ballot |
| `partialDecrypt` | 98 ms | per trustee, per race |
| `homomorphicTally` | <1 ms | 10 ballots |

These are 3.8–4.0× faster than the naive implementation. The largest win came
from noticing that the subgroup membership check was doing a full modular
exponentiation (`v^q mod p`) on every ciphertext and proof commitment — roughly
30 extra modexps per ballot verification. Since `p` is prime, that check is
exactly the **Legendre symbol**, computable via Jacobi in `O(log² p)`. Sliding-
window exponentiation and adaptive fixed-base precomputation for `g` and `y`
supplied the rest. All three are verified against independent reference
implementations.

---

## Why blind signatures

An election must simultaneously prove **eligibility** (only verified voters,
once each) and preserve **secrecy** (nobody learns how anyone voted). Checking
eligibility means knowing who someone is; secrecy means not knowing.

A blind signature dissolves the conflict. The RA signs a credential it cannot
see, so the voter↔credential link **does not exist in any system** — it cannot
be leaked, subpoenaed, or abused by an insider. The unlinkability is
*information-theoretic*, not computational: even an adversary holding the
private key with unbounded compute cannot recover it.

Two implementation details carry most of the weight:

- **PSS encoding is what makes it safe.** Blinding the *raw* message would be
  existentially forgeable, because raw RSA satisfies `sig(a)·sig(b) = sig(a·b)` —
  two voters could combine signatures to mint a credential that was never
  issued. There is a test for exactly this attack.
- **Key consistency is a procedural requirement.** An RA that hands each voter a
  *different* public key can tag ballots without breaking any cryptography. Hence
  one key per election, published with a stable `keyId`, pinned by clients.

---

## Security posture

| Control | Where |
|---|---|
| Admin cannot decrypt or count | ballot box holds no trustee key shares |
| Admin cannot forge the record | ballot box holds no validator keys |
| Admin cannot change the ballot after opening | configuration sealed in block 0; every edit route refuses |
| A closed election stays closed across a restart | close is a chain entry, not a flag in memory |
| A service cannot serve an election it disagrees with | startup compares its keys and validator set against block 0, and refuses |
| Roll additions cannot be hidden | roll frozen, hashed, sealed on-chain and publishable |
| A trustee cannot be made to decrypt the wrong totals | each re-verifies the chain and recomputes the totals before contributing |
| A trustee cannot forge a decryption share | Chaum-Pedersen proof bound to the public share sealed in block 0 |
| No running totals | publishing refused while voting is open; ceremony refuses to start |
| Sybil resistance | closed electoral roll — you cannot be on it unless the EC added you |
| Roll cannot be enumerated | identical response and equal work for every rejection |
| Cast endpoint cannot be used to exhaust CPU | per-address throttling on the write path only; the board stays open |
| Vote/credential never reaches the server | client-side blinding (`packages/crypto`) |
| Malicious voting app detected | Benaloh cast-or-audit (`src/election/benaloh.ts`) |
| One credential per verified voter | unique index + `SELECT … FOR UPDATE` + blinded-message binding |
| No disenfranchisement on signer failure | signing runs inside the transaction |
| National IDs never stored | HMAC under a pepper held outside the DB |
| Cross-election profiling blocked | election ID bound into the identity hash |
| Private key never in the database | `issuer_keys` stores public material only |
| Secrets never logged | `redactedSummary()`; validated at startup, no defaults |
| Append-only audit log | separate table; `REVOKE UPDATE, DELETE` in deployment |
| Rate limiting, strict CORS, security headers, body limits | `src/middleware/` |
| Dependency scanning | `npm audit` — **0 vulnerabilities**, 27 packages total |

**Not yet done, and load-bearing:** TLS 1.3 termination and mTLS between
internal services; real KYC; KMS/HSM-backed signing. See the Known Limitations
section of the [design notes](docs/registration-and-blind-signatures.md#6-known-limitations-stated-honestly).

---

## Design choices worth noting

**No crypto dependencies.** `@dvoting/crypto` uses only WebCrypto globals and
native BigInt. For a voting system, every third-party crypto package is
additional supply-chain surface and additional code an auditor must read.

**No build step.** Node ≥ 22.18 strips TypeScript types natively, so the source
that is reviewed is the source that runs — no transpiler between audit and
execution.

**Hand-written SQL migrations.** The DDL a reviewer audits is the DDL that runs.
This also removed a deprecated dev-dependency chain carrying 4 advisories.

**No JWT library.** Registration tokens are HMAC-SHA256 with no `alg` field, so
the `alg: none` / algorithm-confusion class of bypass is structurally impossible.

---

## Roadmap

**Phase 1 — MVP (complete)**
- [x] Project scaffold
- [x] Blind-signature credential issuance (RFC 9474)
- [x] ElGamal homomorphic ballot encryption (client-side)
- [x] Ballot validity zero-knowledge proofs
- [x] Homomorphic tally
- [x] Threshold decryption (Shamir k-of-n trustees, with proofs)
- [x] Permissioned PoA blockchain ledger
- [x] Public bulletin board with Merkle inclusion proofs
- [x] Ballot-box service (credential check + ledger write)
- [x] Re-voting, last vote counts

**Phase 2 — Hardening**
- [x] Benaloh cast-or-audit challenge (client malware defence)
- [x] Pedersen distributed key generation (removes the trusted dealer)
- [x] Independent validator nodes (own key, own replica, no equivocation)
- [x] HTTP transport — validators run as separate processes over the network
- [x] Durable append-only chain storage, crash-safe with fsync
- [x] Automatic resynchronisation of lagging validators
- [x] View changes — proposer failover, provably fork-free
- [ ] Distributed view-change timeouts and view-change certificates
- [ ] Peer-to-peer gossip and validator-set membership changes
- [ ] CIPHER KYC integration
- [ ] KMS/HSM-backed signing, WAF, distributed rate limiting

**Phase 3 — Submission**
- [x] Public verifiability portal (browser-side independent verification)
- [x] Built-in electoral roll — **no external dependencies of any kind**
- [x] Publicly recountable result sealed on the chain
- [x] Election lifecycle sealed on-chain: config, schedule, one-way close
- [x] Commission console: candidates, roll, freeze, schedule, open, close
- [x] Electoral roll commitment, publishable and independently recomputable
- [x] Trustee service and ceremony — each trustee verifies before it decrypts
- [ ] Threat model writeup, architecture diagrams, demo script
- [ ] Standalone verifier CLI, so an observer needs none of our servers

---

## Layout

```
packages/crypto/
  src/blind-rsa/          RFC 9474 blind signatures
  src/elgamal/            prime-order groups, exponential ElGamal, discrete log
  src/zkp/                Fiat-Shamir transcript, Chaum-Pedersen, disjunctive
  src/threshold/          Shamir, Feldman VSS, trustee partial decryption
  src/election/           ballot construction/verification, tallying
  bench/                  demo-election, election-bench
packages/ledger/
  src/canonical.ts        deterministic binary encoding (never JSON for hashing)
  src/merkle.ts           RFC 6962 Merkle tree + inclusion proofs
  src/validator.ts        Ed25519 validators, PoA validator set
  src/block.ts            block structure, canonical header hashing
  src/chain.ts            validation rules, append-only Ledger
services/registration/    Registration Authority (Hono + Postgres/Drizzle)
  migrations/             hand-written SQL
  src/admin.ts            electoral roll: enrol, revoke, freeze, publish
  src/scripts/            keygen, migrate, demo-voter
services/ballot-box/      ballot box + public bulletin board
  src/election-record.ts  the election's definition, sealed to the chain
  src/ceremony.ts         collects trustee shares, publishes at threshold
  src/admin.ts            commission console API
  public/                 the whole web interface
  src/scripts/            full-election-demo  <- the viva demo
services/trustee/         one process per trustee, holding ONE key share
services/validator/       one process per validator authority
  src/scripts/            generate-validator-key
docs/                     design notes and rationale
```

### Running validators as separate processes

Each authority generates its own key on its own machine and publishes only the
public half:

```bash
node services/validator/src/scripts/generate-validator-key.ts election-commission
```

Then each runs a node, sharing only the public validator set:

```bash
VALIDATOR_ID=election-commission \
ELECTION_ID=dvoting-general-2026 \
VALIDATOR_PRIVATE_KEY=<from keygen stdout> \
VALIDATOR_SET='{"validators":[{"id":"...","publicKey":"..."}, ...]}' \
PROPOSE_TOKEN=<32+ char shared secret> \
CHAIN_PATH=./chain.jsonl \
PORT=8090 \
npm start --workspace @dvoting/validator-node
```

`CHAIN_PATH` gives durable, crash-safe storage and is **required** when
`NODE_ENV=production` — without it a restart loses the election record. On
startup a node re-verifies its whole chain and refuses to serve if verification
fails, so a corrupted chain cannot be laundered into the quorum.
