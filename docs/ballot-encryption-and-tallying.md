# Ballot Encryption, Zero-Knowledge Proofs & Threshold Tallying

Design notes for the E2E-verifiable core. As with the registration layer, every
choice below has a stated reason and the known weaknesses are listed, not hidden.

---

## 1. The chain of guarantees

| Step | Mechanism | What it prevents |
|---|---|---|
| Encrypt on device | Exponential ElGamal | Server never sees a plaintext vote |
| Prove validity | Disjunctive Chaum-Pedersen | Ballot stuffing with inflated values |
| Bind to context | Strong Fiat-Shamir | Ballot cloning / proof splicing |
| Tally | Homomorphic addition | Individual ballots are never decrypted |
| Decrypt | Shamir k-of-n threshold | No single party can read the result |
| Prove decryption | Chaum-Pedersen | A trustee corrupting the tally undetected |

---

## 2. Why *exponential* ElGamal

Standard ElGamal encrypts m as `(g^r, m·y^r)` and is *multiplicatively*
homomorphic. Voting needs addition, so we encrypt `g^m` instead:

```
Enc(m) = (g^r, g^m · y^r)

Enc(m₁) · Enc(m₂) = (g^(r₁+r₂), g^(m₁+m₂) · y^(r₁+r₂)) = Enc(m₁+m₂)
```

Multiplying ciphertexts adds votes. The entire election is summed while every
ballot stays encrypted; only the aggregate is ever decrypted.

**The price:** decryption yields `g^m`, not `m`, so the final step is a discrete
log. That is only tractable because `m` is a vote count bounded by the
electorate — baby-step giant-step in `O(√max)`. Solving a DL over the full
3072-bit group would be infeasible, which is exactly why the scheme is secure
everywhere except this deliberately small range.

### Why the prime-order subgroup

ElGamal over the full group `Z*_p` is **not IND-CPA secure**: the Legendre
symbol is efficiently computable and leaks whether the plaintext is a quadratic
residue — which for a ballot can reveal the vote. We work entirely inside the
order-`q` subgroup of quadratic residues, where DDH is believed hard.

Consequently **every** group element arriving from outside is subgroup-checked.
Skipping that enables a small-subgroup confinement attack: submit a low-order
element and the victim's exponentiation leaks their secret key modulo that small
order, one query at a time.

### Parameters

RFC 3526 MODP groups (Group 14 = 2048-bit, Group 15 = 3072-bit, the default).
These are "nothing up my sleeve" — derived from the binary expansion of π — so
nobody, including this project's author, could have planted a trapdoor. The
constants are verified in CI two independent ways: against Node's OpenSSL-backed
tables, and by re-deriving safe primality and subgroup order from scratch.

3072-bit is the default because it matches the 128-bit security level of the
RSA-3072 issuer key in the registration layer. A chain is only as strong as its
weakest link; pairing a 128-bit signature key with a 112-bit encryption group
would be incoherent.

---

## 3. Ballot validity proofs

Encrypted values are never inspected, so without proofs a voter could encrypt
1000 for their candidate and the homomorphic tally would happily add it. Two
proofs prevent this:

1. **Per candidate:** the ciphertext encrypts 0 or 1.
2. **Aggregate:** the homomorphic sum of all candidate ciphertexts encrypts a
   permitted total (1 for single-choice; a range for approval voting).

Both are the same primitive — a **disjunctive Chaum-Pedersen (CDS) OR-proof**.

### How the OR works

A sigma protocol can be *simulated* for a false statement if you pick the
challenge first: choose challenge and response at random, then solve for the
commitment. The CDS trick lets the prover simulate every branch except the true
one, while a hash pins down the **sum** of all branch challenges:

- false branches: pick `cᵢ`, `sᵢ` at random; back-compute commitments so the
  verification equation holds by construction;
- true branch: commit honestly with random `w`;
- derive `c = H(statement, all commitments)`;
- set the true branch's challenge to `c − Σ(fake challenges) mod q` and answer
  it honestly using the witness.

A cheating prover would need to control the challenge sum before seeing the
hash. Zero-knowledge holds because real and simulated branches are *identically
distributed* — all challenges and responses uniform in `Z_q`. That
indistinguishability **is** the ballot secrecy.

### Strong vs weak Fiat-Shamir — a real vulnerability

**Weak** Fiat-Shamir hashes only the commitments: `c = H(commitments)`.
**Strong** Fiat-Shamir also hashes the statement: `c = H(statement, commitments)`.

Bernhard, Pereira and Warinschi (*"How not to prove yourself"*, ASIACRYPT 2012)
showed **Helios used weak Fiat-Shamir**, letting an attacker forge ballot
validity proofs — because the challenge didn't depend on the ciphertext, a proof
could be manufactured for a statement chosen *after* the commitments were fixed.
Helios was subsequently fixed.

This implementation is strong-Fiat-Shamir *by construction*: the challenge
cannot be produced without first absorbing the statement.

Two further transcript details:

- **Length-prefixed, labelled absorption.** Without it, `("ab","c")` and
  `("a","bc")` hash identically — a concatenation ambiguity letting an attacker
  shift bytes between fields to make two statements collide.
- **Oversampled challenge derivation.** Hashing to exactly `bitlen(q)` bits and
  reducing would bias toward small values. Bias matters beyond tidiness: if the
  real challenge came from a visibly different distribution than the simulated
  ones, the branches would be distinguishable — leaking the vote. We oversample
  by 128 bits before reduction.

### Malleability and replay

ElGamal is malleable *by design* — that is what makes homomorphic tallying
possible — so an attacker can re-randomize a victim's ciphertext into a
fresh-looking one encrypting the same vote. Every proof is therefore bound,
through the transcript, to the election id, the ballot id, **and the full list
of ciphertexts in the ballot**. A cloned or spliced ballot changes that context
and its proofs stop verifying. The ledger must additionally reject duplicate
ballot ids.

---

## 4. Threshold decryption

The election key is split with Shamir secret sharing over `Z_q`. Any `k` of `n`
trustees reconstruct it; any `k−1` learn **nothing** — not "a little", but
nothing in the information-theoretic sense, because for every candidate secret
there is exactly one polynomial through those `k−1` points.

Decryption never materialises the key. Each trustee publishes `α^{xᵢ}`, and
Lagrange interpolation is performed **in the exponent**:

```
∏ (α^{xᵢ})^{λᵢ} = α^(Σ λᵢxᵢ) = α^x       then   g^m = β / α^x
```

### Why partial-decryption proofs are mandatory

A trustee submitting a random group element instead of `α^{xᵢ}` corrupts the
final tally. Because the tally is decrypted only once, at the end, the
corruption is **indistinguishable from a legitimate result** — there is nothing
to compare against. Each partial therefore carries a Chaum-Pedersen proof that
`log_g(hᵢ) = log_α(dᵢ)`: "the exponent I just used is the one I published at
setup". A bad partial is rejected immediately and is attributable.

### Feldman VSS

The dealer publishes commitments `C_j = g^{a_j}` to the polynomial
coefficients, so each trustee can check `g^{f(i)} = ∏ C_j^{i^j}`. This detects a
dealer distributing inconsistent shares, which would otherwise only surface at
decryption time — when the election is over and the result already wrong.

---

## 5. Performance

Ballot casting happens on a voter's device, so its cost is a usability
constraint. Measured at 3072-bit, 4 candidates (`bench/election-bench.ts`):

| Operation | Before optimization | After | Speedup |
|---|---|---|---|
| `modPow` | 40.8 ms | 27.8 ms | 1.5× |
| `createBallot` (on device) | 1838 ms | **485 ms** | 3.8× |
| `verifyBallot` (per observer) | 2911 ms | **730 ms** | 4.0× |
| `partialDecrypt` | 237 ms | 98 ms | 2.4× |
| `decryptTally` | 4494 ms | 1408 ms | 3.2× |

Three optimizations, all verified against independent reference implementations
in `test/bigint-optimized.test.ts`:

1. **Legendre symbol for subgroup checks.** `isInSubgroup` originally computed
   `v^q mod p` — a full modular exponentiation — on every ciphertext component
   and proof commitment, ~30 extra modexps per ballot verification. Because `p`
   is prime, this is exactly the Legendre symbol, computable via Jacobi in
   `O(log² p)`. This was the single largest win.
2. **Sliding-window exponentiation** (w=5): ~25% across the board, including the
   RSA blind signatures.
3. **Adaptive fixed-base precomputation** for `g` and the election key `y`,
   which account for roughly half of all exponentiations. Tables are built only
   after a base proves hot (8 uses), because building one costs ~3
   exponentiations and would otherwise penalise one-off bases.

---

## 5b. Publishing a recountable result

An *announced* result is exactly as trustworthy as the people announcing it —
which is the thing end-to-end verifiability exists to remove. So the result is
sealed onto the chain as **evidence**, not as an assertion: the encrypted
per-candidate totals, every trustee's partial decryption *with its
zero-knowledge proof*, the trustees' public shares, and the plaintext counts.

`verifyPublishedTally` then redoes the entire count from the chain alone,
trusting nothing in the published tally:

1. re-reads every ballot and re-verifies its proofs;
2. re-applies the re-voting rule and checks the published counted set;
3. recomputes the homomorphic totals and checks they match;
4. re-verifies each trustee's decryption proof;
5. re-combines the partials and checks the announced numbers.

An observer with the chain file needs no secrets and no cooperation. Tests cover
each way a result could be faked — announcing different numbers, swapping in
different encrypted totals, omitting counted ballots, forging a trustee proof,
inventing a trustee, and publishing below the threshold.

Two operational rules fall out of this:

- **A tally cannot be published while voting is open.** A running total lets late
  voters see the state of the race, and lets an operator decide whether to keep
  counting based on who is winning.
- **A tally cannot be published twice.** A second, different result would make
  the record ambiguous — the same reason a ledger never rewrites.

---

## 6. Known limitations (stated honestly)

- **Dealer-based setup is no longer the default.** `setupTrustees` (trusted
  dealer) is retained for tests and simple demos, but the election path now uses
  **Pedersen distributed key generation** — see
  [threshold-key-generation.md](threshold-key-generation.md). With DKG the
  private key is never assembled anywhere, at any point, so "no single party can
  decrypt" becomes a property of the protocol rather than a promise about a
  ceremony. DKG carries its own documented caveat (a known, published bias that
  does not apply to threshold ElGamal).

- **BigInt is not constant-time.** Same limitation as the registration layer.
  Trustee decryption should move to an HSM for any binding election.

- **Single-ballot tallies leak.** With one ballot, the homomorphic aggregate
  *is* that ballot. This is inherent to any homomorphic tally, not a flaw in the
  encryption — but a real election must refuse to decrypt a tally below a
  minimum ballot count.

- **No mixnet.** Homomorphic tallying supports only additive contests
  (single-choice, approval). Ranked-choice or write-in ballots would require a
  verifiable shuffle, which is not implemented.

- **Client-side malware is mitigated, not solved.** A compromised device can
  encrypt a different vote than the voter selected, and every proof here will be
  perfectly valid — these proofs establish that the ciphertext is well-formed,
  not that it reflects the voter's intent. The **Benaloh cast-or-audit
  challenge** now addresses this probabilistically; see
  [cast-as-intended.md](cast-as-intended.md). Its own load-bearing caveat is
  that the audit must run on a device the malicious app does not control. MIT
  flags this as an open problem for *all* internet voting.

---

## 7. Test coverage map

| Property | Test |
|---|---|
| Group constants genuine | `match Node's own RFC 3526 tables` |
| Safe prime + subgroup order | `are safe primes with a prime-order subgroup` |
| Additive homomorphism | `is additively homomorphic` |
| Small-subgroup defence | `rejects ciphertexts outside the subgroup` |
| Ballot stuffing blocked | `rejects a ballot stuffed with an inflated vote` |
| Clone/replay blocked | `rejects a ballot cloned by re-randomization` |
| Proof splicing blocked | `rejects proofs spliced between two ballots` |
| Weak-Fiat-Shamir defence | `rejects a proof bound to a different context` |
| Transcript ambiguity | `is not vulnerable to field-boundary ambiguity` |
| Threshold secrecy | `CANNOT decrypt below the threshold` |
| Malicious trustee caught | `REJECTS a malicious trustee's forged partial decryption` |
| Dishonest dealer caught | `detects a tampered share` |
| Full election correctness | `runs end to end: encrypt -> prove -> tally -> threshold decrypt` |
| Independent recount | `accepts an honest result` |
| Fabricated numbers caught | `REJECTS announced numbers that do not match the ballots` |
| Substituted totals caught | `REJECTS encrypted totals that are not the sum of the ballots` |
| Dropped ballots caught | `REJECTS a tally that omits counted ballots` |
| No running totals | `REFUSES to publish while the election is still open` |
| Optimizations correct | `test/bigint-optimized.test.ts` (vs reference impls) |
