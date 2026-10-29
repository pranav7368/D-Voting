# Design notes

Why the system is built the way it is. The protocol-level rationale is in the topic documents listed in the [README](../README.md#documentation).

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

## Why it is fast enough

Ballot casting runs on the voter's device, so its cost is a usability
constraint, not a vanity metric. The optimised code is 3.8–4.0× faster than the naive implementation. The largest win came
from noticing that the subgroup membership check was doing a full modular
exponentiation (`v^q mod p`) on every ciphertext and proof commitment — roughly
30 extra modexps per ballot verification. Since `p` is prime, that check is
exactly the **Legendre symbol**, computable via Jacobi in `O(log² p)`. Sliding-
window exponentiation and adaptive fixed-base precomputation for `g` and `y`
supplied the rest. All three are verified against independent reference
implementations.

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

## Security controls

Every row is enforced in code and most have an attack test behind them. The adversaries and residual risks are in the [threat model](threat-model.md).

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
| Dependency scanning | `npm audit --omit=dev` — **0 known production vulnerabilities** |

**Not yet done, and load-bearing:** TLS 1.3 termination and mTLS between
internal services; real KYC; KMS/HSM-backed signing. See the Known Limitations
section of [registration and blind signatures](registration-and-blind-signatures.md#6-known-limitations-stated-honestly).
