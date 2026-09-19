# Threshold Key Generation: removing the dealer

Design notes for Pedersen Distributed Key Generation — how the election key gets
created without anyone ever holding it.

---

## 1. The problem with a dealer

The original `setupTrustees` generates the election private key in one place,
splits it with Shamir, and trusts that process to erase it.

Feldman VSS closes half the gap: trustees can verify their shares are mutually
consistent, so a dealer cannot distribute *bad* shares undetected. It cannot
close the other half — **the dealer saw the key**.

That makes the strongest supportable claim "no single party can decrypt *after a
correctly-run ceremony*". That is a procedural promise about a moment in time,
not a cryptographic guarantee. For a system whose headline property is
"not even the Election Commission can decrypt alone", that gap matters.

---

## 2. The fix: nobody generates the key

In a DKG the key is never generated anywhere. Each participant contributes its
own random polynomial, and the election key is the **sum** of everyone's
contributions:

```
x = Σ z_i          y = Π g^{z_i}
```

Every participant knows their own `z_i` and their share `x_j` of the total.
Nobody — at any point, including setup — ever holds `x`.

### Protocol

**Round 1.** Participant `i` picks a random degree-`(t−1)` polynomial `f_i` with
`f_i(0) = z_i`, broadcasts Feldman commitments `C_{i,k} = g^{a_{i,k}}`, and
privately sends `s_{i,j} = f_i(j)` to each participant `j`.

**Round 2.** Participant `j` verifies every received share against the sender's
broadcast commitments:

```
g^{s_{i,j}} == Π_k C_{i,k}^{j^k}
```

A share that fails is a complaint, and the sender is disqualified. The proof is
public and checkable by everyone, so a *false* accusation is impossible.

**Output.** Let `Q` be the qualified set:

| Value | Formula | Who computes it |
|---|---|---|
| joint public key | `y = Π_{i∈Q} C_{i,0}` | everyone |
| private share | `x_j = Σ_{i∈Q} s_{i,j}` | participant `j` only |
| public share | `h_j = g^{x_j} = Π_{i∈Q} Π_k C_{i,k}^{j^k}` | everyone |

That last row matters: **every participant's public share is derivable from
broadcast data alone**. Nobody has to be trusted to publish it honestly, which is
what makes the partial-decryption proofs at tally time checkable — the verifier
already knows what `g^{x_j}` must be.

### Why it's a drop-in replacement

The shares `x_j` lie on `F(X) = Σ_{i∈Q} f_i(X)`, a degree-`(t−1)` polynomial with
`F(0) = x`. So any `t` of them reconstruct `x` by Lagrange interpolation —
exactly the same threshold decryption path as before. Nothing downstream
changes: `partialDecrypt`, `verifyPartialDecryption` and
`combinePartialDecryptions` all work unmodified.

### Where the shares actually live

A threshold means nothing if all `n` shares sit inside one service, so each
trustee is **its own process** ([`services/trustee`](../../services/trustee/))
holding exactly one share, driven by one operator, with its own console and its
own token — one the election commission does not have.

The public shares `h_j` are sealed into the election's configuration block when
the poll opens, which is what lets anyone check a partial decryption later. See
[election-lifecycle-and-administration.md](election-lifecycle-and-administration.md)
for the ceremony itself, including what each trustee verifies for itself before
it is willing to apply its share.

---

## 3. Surviving a cheater

A participant who sends a share inconsistent with their commitments is caught by
the recipient and disqualified. The ceremony then **continues without them** —
the joint key is simply the product over the qualified set, and the cheater's
contribution is excluded entirely.

Two failure modes are handled explicitly:

- **Withholding a share** is treated identically to sending a bad one.
- **Too few qualified participants** aborts the ceremony loudly rather than
  producing a key that could never reach the threshold. Better to re-run setup
  than to discover at tally time that the election is undecryptable.

Tested by `disqualifies a participant who sends an inconsistent share`,
`still produces a working key from the qualified participants`, and
`FAILS the ceremony when too few participants qualify`.

---

## 4. Known limitation — state this precisely

Gennaro, Jarecki, Krawczyk and Rabin showed that Pedersen's DKG does **not**
produce a uniformly distributed public key. A rushing adversary who sees others'
contributions before deciding whether to disqualify a participant can bias the
distribution of `y`.

Be precise about what this does and does not mean:

- It does **not** let the adversary learn `x`.
- It does **not** let them steer `y` to a chosen value.
- It **does** skew some bits of `y`'s distribution.

The same authors later showed (*"Secure Applications of Pedersen's Distributed
Key Generation Protocol"*, CT-RSA 2003) that this bias is harmless for a class of
applications **including threshold ElGamal decryption** — which is exactly the
use here. The fully unbiased variant requires an extra commit-then-reveal round.

That is the honest position: a known, published, quantified weakness that does
not apply to this use case. Being able to name the paper and explain why it
doesn't bite is worth more in a viva than pretending the issue doesn't exist.

### Other limitations

- **The in-process `runDkg` is for tests and demos only.** It momentarily sees
  every share, which defeats the entire purpose. A real ceremony runs
  `createDkgContribution` on each participant's own machine and exchanges
  commitments and shares over the network. The individual functions are the ones
  a distributed deployment calls; `runDkg` just wires them together.

- **Private shares need a confidential, authenticated channel.** An eavesdropper
  who collects `t` shares in transit reconstructs the election key. The DKG
  assumes secure pairwise channels; providing them is a deployment concern.

- **No proactive refresh.** Shares are fixed for the life of the election. A
  long-lived deployment would want proactive secret sharing, where shares are
  periodically re-randomised so an attacker must compromise `t` trustees within
  a single epoch rather than over the whole election period.

---

## 5. Test coverage map

| Property | Test |
|---|---|
| Works with no dealer | `produces a working joint key with no dealer` |
| Nobody holds the key | `NO participant ever holds the election private key` |
| Any qualifying subset decrypts | `works with any qualifying subset of trustees` |
| Minority learns nothing | `CANNOT decrypt below the threshold` |
| Public shares are derivable | `derives every public share from broadcast data alone` |
| Compatible with tally proofs | `produces partial decryptions that verify against the derived public shares` |
| Bad share caught | `disqualifies a participant who sends an inconsistent share` |
| Withheld share caught | `disqualifies a participant who withholds a share` |
| Ceremony survives a cheater | `still produces a working key from the qualified participants` |
| Cheater excluded from key | `excludes the cheater's contribution from the joint key` |
| Fails loudly when unusable | `FAILS the ceremony when too few participants qualify` |
