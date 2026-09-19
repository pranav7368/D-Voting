# Cast-as-Intended: the Benaloh Challenge

Design notes for the client-malware defence — the last major threat in the
model, and the one MIT flags as unsolved for *all* internet voting.

---

## 1. The problem nothing else solves

Every other defence in D-Voting protects the ballot **after** it is encrypted.
None protects the moment of encryption itself.

A compromised voting app can simply encrypt Bob when the voter selected Alice:

- the ciphertext is perfectly well-formed;
- the zero-knowledge validity proofs **all verify** — they prove the ciphertext
  encrypts 0 or 1, *not* that it encrypts what the voter chose;
- the credential is genuine, the ledger records it, the tally counts it;
- the result is wrong and **nothing anywhere is detectably broken**.

This is worth stating precisely in a viva, because it is counter-intuitive: more
cryptography does not help. The proofs are working exactly as designed. The gap
is between the voter's *intent* and the app's *input*.

There is a test asserting exactly this — `the fraudulent ballot passes every
other check` — so the problem is demonstrated before the solution is.

---

## 2. The defence

The client must **commit** to an encrypted ballot before learning what will
happen to it. Only then does the voter choose:

| Choice | What happens |
|---|---|
| **Cast** | Submit it. The randomness is destroyed; the vote is secret forever. |
| **Audit** | The client must reveal its randomness. The voter re-encrypts their intended selections with it and demands a byte-exact match. |

ElGamal is deterministic given `(message, randomness)`, so a match is *proof*
that the ballot encodes exactly those selections — and a mismatch is proof that
it does not.

An audited ballot is **spoiled**: its randomness is public, so anyone can
decrypt it. It can never be cast, and the voter starts over.

### Why it works

The client cannot know in advance whether a ballot will be audited or cast, so
it cannot cheat only on the ones nobody will check. A client cheating on a
fraction `p` of ballots is caught by any single audit with probability `p`:

```
survival = (1 − p)^audits
```

Cheating on 10% of ballots survives 20 audits only 12% of the time. Across an
electorate, systematic fraud is detected with overwhelming probability.
`cheatSurvivalProbability()` computes this, and is what you would use to tell
voters how many audits are worth performing.

### The commitment matters

Without it, a malicious client could produce a dishonest ballot, see the voter
ask for an audit, and reveal the secrets of a *different, honest* ballot
instead. `auditAgainstCommitment()` binds the audit to the commitment the voter
recorded, so the substitution fails. Tested by `catches the client substituting
a different ballot at audit time`.

---

## 3. Two checks, and why they must stay separate

This is the subtlest part of the design, and the easiest to get wrong.

**Check 1 — anyone can perform it.** Does the ciphertext match the revealed
randomness? This establishes *what the ballot encrypts*. The ballot box runs it,
publishes the spoiled ballot with its randomness, and any observer can re-run it
from the chain.

**Check 2 — only the voter can perform it.** Is that what I chose? This
compares the encrypted selections against the voter's actual intent.

**The ballot box is deliberately never given the voter's intent.** Passing
`expectedSelections` to the server would hand it a plaintext vote and destroy
ballot secrecy — the exact property the whole system exists to protect. So
`BallotBox.spoil()` calls `auditBallot()` *without* that argument, and returns
`encryptionConsistent` plus `encodedSelections`. The voter compares.

A vote-swapping client is *internally consistent*, so check 1 alone cannot catch
it. That is not a weakness — it is the privacy boundary working correctly.

```
  [check 1 - anyone] ciphertext matches revealed randomness: true
                     ballot provably encrypts: Bob
  [check 2 - voter]  matches what I chose: false
                     the ballot encrypts Bob but the voter selected Alice
```

---

## 4. Interaction with the rest of the system

- **Spoiled ballot ids are burned permanently.** Casting a ballot whose
  randomness is public would put a publicly-readable vote in the tally. The
  ballot box refuses with `ballot_spoiled`, both before and after the spoiled
  record is sealed on chain.
- **Already-cast ballots cannot be audited.** Otherwise a coercer could force a
  voter to "audit" their cast ballot and thereby reveal how they voted.
- **Spoiled ballots are excluded from the tally** — they are recorded under a
  different entry kind (`spoiled-ballot`) that `tallyFromChain` ignores.
- **Failed audits are recorded as evidence**, not quietly discarded. An
  inconsistent audit is proof of a misbehaving client and belongs on the public
  record.

---

## 5. Known limitations (state these plainly)

- **The audit must run somewhere the malicious app does not control.** If the
  voter verifies on the same compromised device, the app can simply lie about
  the result. A real deployment needs the check performed on a separate device
  or by an independent verifier application. This module provides the
  verification function; *where it runs* is a deployment property, not a
  cryptographic one. **This is the single most important caveat.**

- **It cannot stop UI deception.** An app that displays a different candidate
  list than it encrypts against defeats the audit, because the voter's "intent"
  is captured through the compromised UI. That is a UI-integrity problem outside
  the reach of cryptography.

- **It is probabilistic, not absolute.** A client that cheats rarely may survive
  a given voter's audits. The guarantee is statistical and electorate-wide, not
  a per-ballot certainty.

- **It depends on voters actually auditing.** A defence nobody exercises detects
  nothing. Real deployments must make auditing prominent and easy, which is a
  usability problem as much as a security one.

- **Voter-verified paper remains the gold standard.** Security researchers still
  recommend a physical audit trail as the backup for binding elections. This
  system has none.

---

## 6. Test coverage map

| Property | Test |
|---|---|
| The problem is real | `the fraudulent ballot passes every other check` |
| Honest client passes | `audits successfully when the ballot encodes the voter's choice` |
| Client lying about randomness | `catches the client when it lies about what it encrypted` |
| Client swapping the vote | `catches the client when it reveals the truth (a vote it was not told to cast)` |
| Ballot substitution at audit | `catches the client substituting a different ballot at audit time` |
| Privacy boundary | `publishes WHAT a ballot encrypted, without learning the voter's intent` |
| Spoiled ballots uncastable | `REFUSES to cast a ballot that was audited` |
| Cast ballots unauditable | `REFUSES to audit a ballot that was already cast` |
| Audit-then-cast flow | `lets the voter audit, then cast a fresh ballot successfully` |
| Spoiled excluded from tally | `excludes spoiled ballots from the tally` |
| Evidence retained | `records an INCONSISTENT audit as evidence rather than dropping it` |
| Detection probability | `computes the chance a cheating client survives auditing` |
