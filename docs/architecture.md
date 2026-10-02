# Architecture

How the parts of D-Voting fit together, who holds which key, and where the trust
boundaries are. The diagrams are Mermaid and render on GitHub. For why each
decision was made, see the subsystem notes linked from the [README](../README.md);
for what each part defends against, see the [threat model](threat-model.md).

---

## 1. Components and who holds what

Each box is a separate process. In a real deployment each one is a separate
organisation on separate hardware. `npm run dev` runs them all on one machine,
on the ports shown.

```mermaid
flowchart LR
  subgraph Voter["Voter's device"]
    B["Browser<br/>/vote · /verify<br/><i>choice, credential, randomness<br/>never leave this tab</i>"]
  end

  subgraph EC["Election commission"]
    BB["Ballot box + bulletin board<br/>:8082<br/><b>holds no keys</b>"]
    ADM["/admin console"]
  end

  RA["Registration Authority<br/>:8081<br/><b>issuer private key</b><br/>roll (HMACs only)"]

  subgraph VAL["Validators (PoA, 3-of-4)"]
    V1["election-commission<br/>:8090"]
    V2["observer-press<br/>:8091"]
    V3["observer-university<br/>:8092"]
    V4["observer-ngo<br/>:8093"]
  end

  subgraph TR["Trustees (3-of-5)"]
    T1["Trustee 1<br/>:8100"]
    T2["Trustee 2<br/>:8101"]
    T3["…<br/>:8102–8104"]
  end

  OBS["Any observer<br/>dvoting-verify CLI"]

  B -- "polling card → blind signature" --> RA
  B -- "encrypted ballot + ZK proofs" --> BB
  ADM --> BB
  BB -- "propose / attest" --> VAL
  TR -- "partial decryptions + proofs" --> BB
  BB -- "public board" --> TR
  BB -- "public board" --> OBS
  BB -- "public board" --> B
```

| Party | Holds | Can do alone | Cannot do |
|---|---|---|---|
| Voter's browser | choice, credential, blinding factor, randomness | build and audit its own ballot | — |
| Registration Authority | issuer private key, roll HMACs, pepper | issue one credential per roll entry | see the credential it signed |
| Ballot box | nothing secret | accept, reject, queue ballots; serve the board | sign a block, decrypt anything |
| Validator | one Ed25519 key, own chain replica | refuse a bad block | produce a block alone |
| Trustee | one Shamir key share | refuse to decrypt | decrypt alone |
| Observer | the public board, optionally a pinned validator set | recount everything | — |

---

## 2. Packages

```mermaid
flowchart TB
  crypto["@dvoting/crypto<br/>blind RSA · ElGamal · ZKPs · DKG · threshold · Benaloh<br/><i>WebCrypto + BigInt, no dependencies</i>"]
  ledger["@dvoting/ledger<br/>blocks · RFC 6962 Merkle · Ed25519 PoA · view changes · file store"]
  ra["services/registration"]
  bb["services/ballot-box"]
  val["services/validator"]
  tr["services/trustee"]
  ver["@dvoting/verifier<br/>standalone recount CLI"]
  web["browser bundle<br/>dvoting-crypto.js"]

  ledger --> crypto
  ra --> crypto
  bb --> crypto
  bb --> ledger
  val --> ledger
  tr --> ledger
  ver --> bb
  ver --> ra
  ver --> ledger
  web -. "built from" .-> crypto
```

The browser runs the **same** `@dvoting/crypto` source as the server and the
tests, bundled unminified by `npm run build:web`.

---

## 3. Casting a ballot

```mermaid
sequenceDiagram
  autonumber
  actor V as Voter (browser)
  participant RA as Registration Authority
  participant BB as Ballot box
  participant VN as Validators

  V->>BB: GET /v1/election
  Note over V: pin issuer keyId and election key<br/>from the sealed record
  V->>RA: POST /v1/register (roll id, enrolment code)
  RA-->>V: short-lived registration token
  Note over V: credential = random<br/>blinded = blind(credential)
  V->>RA: POST /v1/credential/issue (token, blinded)
  RA-->>V: blind signature
  Note over V: unblind → signature on a credential<br/>the RA has never seen
  Note over V: encrypt choice, prove each ciphertext is 0/1<br/>and the sum is within limits
  opt Benaloh audit (any number of times)
    V->>BB: POST /v1/ballots/audit
    BB-->>V: ballot spoiled and published
    Note over V: check the revealed randomness<br/>reproduces the choice
  end
  V->>BB: POST /v1/ballots (credential, signature, ballot)
  Note over BB: verify blind signature, ZK proofs,<br/>binding to credential, not a replay
  BB->>VN: propose block (scheduled proposer)
  Note over VN: each re-validates every ballot<br/>against its own replica
  VN-->>BB: ≥ quorum attestations
  BB-->>V: tracking code
  V->>BB: GET /v1/bulletin/ballots/:code
  Note over V: re-hash header, check signatures,<br/>walk the Merkle path locally
```

---

## 4. Sealing a block, with failover

```mermaid
sequenceDiagram
  participant BB as Ballot box (coordinator)
  participant P0 as Proposer, view 0
  participant P1 as Proposer, view 1
  participant O as Other validators

  BB->>P0: propose(height h, entries, view 0)
  P0--xBB: unreachable
  Note over BB: no block exists at view 0,<br/>so advancing is safe
  BB->>P1: propose(height h, entries, view 1)
  P1-->>BB: signed block
  BB->>O: attest(block)
  Note over O: refuse if: wrong proposer for view,<br/>bad Merkle root, replayed entry,<br/>or already signed another block at h
  O-->>BB: attestations
  Note over BB: ≥ 3 of 4 → commit and broadcast
```

Two rules make failover fork-free: any two quorums of more than 2/3 overlap, and
no validator signs two different blocks at one height. See
[ledger notes](ledger-and-bulletin-board.md).

---

## 5. The election's life on the chain

```mermaid
stateDiagram-v2
  [*] --> setup
  setup --> voting: open, block 0 sealed
  voting --> voting: ballots sealed
  voting --> closed: close record
  closed --> published: k trustees contribute
  published --> [*]
  note right of closed
    irreversible: a restart
    cannot reopen it
  end note
```

| Entry kind | Written when | Contains |
|---|---|---|
| `election-config` | open (block 0) | the whole sealed definition |
| `ballot` | each cast | encrypted choices, proofs, credential fingerprint |
| `spoiled-ballot` | each audit | the ballot and its revealed randomness |
| `election-closed` | close | reason, time, final height |
| `tally-result` | last trustee share | totals, every partial decryption and proof, results |

---

## 6. Counting

```mermaid
sequenceDiagram
  participant BB as Ballot box
  participant T as Trustee i
  participant O as Observer

  T->>BB: GET /v1/ceremony, /v1/election, every block
  Note over T: rebuild chain locally (quorum check)<br/>confirm close record<br/>confirm own share is in sealed roster<br/>recompute encrypted totals
  alt totals match
    T->>BB: partial decryptions + Chaum-Pedersen proofs
  else anything differs
    Note over T: refuse, and say why
  end
  Note over BB: verify each proof against<br/>the sealed public share
  Note over BB: k valid shares → combine,<br/>seal tally-result
  O->>BB: download every block
  Note over O: dvoting-verify:<br/>quorum · config · close · every ballot's proofs ·<br/>re-voting rule · totals · decryption proofs · result
```

---

## 7. Trust boundaries

```mermaid
flowchart LR
  subgraph TB1["Trusted only by the voter"]
    browser["Voter's browser"]
  end
  subgraph TB2["Trusted for availability, not correctness"]
    bb["Ballot box"]
  end
  subgraph TB3["Trusted while fewer than a quorum are faulty"]
    vals["Validators"]
  end
  subgraph TB4["Trusted while fewer than k collude"]
    trs["Trustees"]
  end
  subgraph TB5["Trusted for eligibility"]
    ra["Registration Authority"]
  end
  subgraph TB6["Trusts nothing but math + a pinned validator set"]
    obs["Observer / verifier"]
  end
  browser --> bb --> vals
  trs --> bb
  ra -.-> browser
  bb --> obs
```

The ballot box sits in the least-trusted position on purpose. It can refuse
service, which is visible. It cannot change the outcome undetectably, because
every output it produces is checked by someone who does not trust it.

---

## 8. Storage

| Data | Where | Durability |
|---|---|---|
| Chain | Validator and ballot-box replicas; `CHAIN_PATH` file store (append-only, fsync) | Survives restarts; any replica or observer copy is enough to recount |
| Roll, issuance records, audit log | RA: Postgres (production) or memory (dev) | Postgres with `REVOKE UPDATE, DELETE` on the audit log |
| Keys | Each party's own environment | Not in any database |
| Exported board | `dvoting-verify --save board.json` | Verifiable offline indefinitely |
