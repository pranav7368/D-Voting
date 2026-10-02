# Threat Model

This document states what D-Voting defends against, what it assumes, and what it
does not defend against. Each defence is tied to the code that enforces it and to
a test written from the attacker's side. A defence without a failing-attack test
is listed as an assumption, not a guarantee.

See also: [architecture](architecture.md) for the components and trust
boundaries, and the per-subsystem design notes linked from the
[README](../README.md).

---

## 1. Security goals

| Goal | Meaning in this system |
|---|---|
| **Eligibility** | Only voters on the frozen electoral roll can cast a ballot that counts, and each roll entry yields at most one credential. |
| **Ballot secrecy** | No party, and no coalition below the trustee threshold, can learn how an individual voted. |
| **Cast-as-intended** | A voter can detect a voting app that encrypts something other than their choice. |
| **Recorded-as-cast** | A voter can prove their ballot is on the public record, unchanged. |
| **Counted-as-recorded** | Anyone can recompute the result from the public record and detect a wrong announced number. |
| **Tamper evidence** | Any change to the record after it is sealed is detectable by any observer. |
| **Immutability of the rules** | Candidates, selection limits, keys, trustees, validators and roll commitment cannot change once the poll opens. |

The first five are the standard end-to-end-verifiability properties. The last
two are what the permissioned ledger adds.

---

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Issuer private key (RA) | RA process memory / env | Forging it mints credentials, i.e. fake voters |
| Enrolment codes | Printed polling cards; only HMACs stored | Possession lets someone register as that voter |
| Identity pepper | RA env, outside the database | Without it, a DB dump cannot be linked to national IDs |
| Trustee key shares | One per trustee process | k of them decrypt the totals |
| Validator signing keys | One per validator process | A quorum of them can sign blocks |
| Voter's choice, credential, blinding factor, encryption randomness | The voter's browser tab only | Any of these leaking breaks secrecy or unlinkability |
| The chain | Every validator's replica, the ballot box, every observer who downloads it | It is the election record |

---

## 3. Adversaries

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | **Outside attacker** | Network access to every public endpoint; can submit arbitrary requests at volume. |
| A2 | **Malicious voter** | Holds a valid credential; tries to vote twice, inflate a vote, or replay someone else's ballot. |
| A3 | **Malicious voting client** | Controls the code running in the voter's browser (compromised device, tampered bundle). |
| A4 | **Corrupt election commission / ballot-box operator** | Full control of the ballot-box server and admin console. |
| A5 | **Corrupt Registration Authority** | Full control of the RA server and its database. |
| A6 | **Corrupt validators** | Up to *f* of *n* validators, where *n* > 3*f* (1 of 4 in the default deployment). |
| A7 | **Corrupt trustees** | Up to *k*−1 of *n* trustees (2 of 5 by default). |
| A8 | **Coercer / vote buyer** | Can pressure a voter and watch the public bulletin board. |
| A9 | **Forger of the record** | Hands an observer a fabricated chain file. |

---

## 4. Threats and defences

### 4.1 Eligibility (A1, A2, A5)

| Threat | Defence | Enforced in | Evidence |
|---|---|---|---|
| Vote without being on the roll | Closed electoral roll; enrolment code checked against its HMAC | `services/registration/src/eligibility/` | `roll-admin.test.ts`, `registration.test.ts` |
| Obtain two credentials | Unique issuance per roll entry; `SELECT … FOR UPDATE`; blinded message bound to the issuance | `services/registration/src/repo/` | `refuses a second DIFFERENT blinded message under the same token` |
| Forge a credential by combining signatures | RSA-PSS blind signatures (RFC 9474), never raw RSA | `packages/crypto/src/blind-rsa/` | `defeats the multiplicative forgery that breaks textbook blind RSA` |
| Use a credential from another issuer | Ballot box verifies against the issuer key sealed in block 0 | `services/ballot-box/src/ballot-box.ts` | `REJECTS a credential signed by a different Registration Authority` |
| Enumerate the roll | Identical response and equal work for every rejection | `services/registration/src/app.ts` | `gives an IDENTICAL response for an unknown roll id and a wrong code` |
| Commission adds fake voters after freezing | Roll commitment sealed in block 0; recomputable from the published roll | `roll-commitment.ts`, `election-record.ts`, `packages/verifier` | `detects a roll that is not the one committed to` |

### 4.2 Ballot validity (A2, A3)

| Threat | Defence | Evidence |
|---|---|---|
| Inflated vote (e.g. 5 votes for one candidate) | Disjunctive Chaum-Pedersen proof that every ciphertext encrypts 0 or 1, plus a proof on the sum | `rejects a ballot stuffed with an inflated vote` |
| Ciphertext swapped after proving | Strong Fiat-Shamir binds the proof to the ciphertext, election and credential | `rejects a ballot whose ciphertext was swapped after proving`, `rejects proofs spliced between two ballots` |
| Clone someone else's ballot | Proof binds to the credential fingerprint and ballot id | `rejects a ballot cloned by re-randomization`, `rejects a ballot re-cast under a different credential` |
| Replay a ballot | Chain-wide entry uniqueness | `rejects a ballot replayed under a new ballot id`, `refuses a block replaying an existing entry id` |
| Small-subgroup attacks | Subgroup membership (Legendre symbol) on every element | `rejects out-of-subgroup ciphertexts in a ballot` |

### 4.3 Secrecy (A4, A5, A6, A7)

| Threat | Defence | Evidence |
|---|---|---|
| RA links voter to credential | Blind signature: the RA never sees the credential. Unlinkability is information-theoretic. | `blind-rsa.test.ts` |
| Server sees the vote | Encrypted in the browser; plaintext never sent | `services/ballot-box/public/vote-page.js`; `serves the browser crypto bundle, without server-only key material` |
| Commission decrypts a ballot | Ballot box holds no key shares; trustees have no route that decrypts a caller-chosen ciphertext | `REFUSES a total that is not the sum of the ballots on the chain` |
| Fewer than *k* trustees collude | Shamir *k*-of-*n*; key generated by Pedersen DKG, never assembled | `CANNOT decrypt below the threshold`, `dkg.test.ts` |
| Running totals leak partial results | Ceremony refuses to start while voting is open | `REFUSES to begin while voting is still open`, `offers nothing while voting is open` |

### 4.4 Cast-as-intended (A3)

| Threat | Defence | Evidence |
|---|---|---|
| Client encrypts a different choice | Benaloh cast-or-audit: the client commits before learning whether it will be audited | `catches the client when it lies about what it encrypted` |
| Client substitutes a ballot at audit time | Audit checks against the committed fingerprint | `catches the client substituting a different ballot at audit time` |
| An audited ballot is then cast | Spoiled ballots are sealed and refused forever | `REFUSES to cast a ballot that was audited` |

**Residual:** the audit must be checked on a device the malicious client does not
control. See [cast-as-intended](cast-as-intended.md) §5.

### 4.5 Integrity of the record (A4, A6, A9)

| Threat | Defence | Evidence |
|---|---|---|
| Alter a sealed ballot | Merkle root in a signed header; any observer recomputes it | `DETECTS tampering with a historical block`, `detects a ballot altered after it was sealed` |
| Remove a block | Hash linkage | `DETECTS a removed block` |
| Fork the chain via proposer failover | >2/3 quorum intersection + validators refuse to sign two blocks at one height | `CANNOT fork: two views at one height cannot both reach quorum` |
| Fewer than a quorum of validators forge a block | Signature quorum checked by every replica and every observer | `rejects a block below quorum`, `rejects duplicate attestations faking a quorum` |
| Commission changes the rules mid-election | Configuration sealed in block 0; services refuse to run if their config disagrees | `REFUSES to edit the ballot after the poll has opened` |
| Commission reopens a closed poll | Close is a chain entry, not a flag | `CANNOT be reopened by restarting the service after it was closed` |
| Ballot slipped in after the close | Verifier rejects any ballot after the close record | `packages/verifier/src/verify.ts` |

### 4.6 Integrity of the count (A4, A6, A7)

| Threat | Defence | Evidence |
|---|---|---|
| Ballot box drops or adds ballots in the count | Counted set re-derived from the chain by every trustee and every observer | `REFUSES when the ballot box misreports how many ballots were counted` |
| Ballot box offers trustees the wrong totals | Each trustee recomputes the totals from the chain before applying its share | `REFUSES a total that is not the sum of the ballots on the chain` |
| A trustee submits a bad decryption share | Chaum-Pedersen proof against the public share sealed in block 0 | `REJECTS a malicious trustee's forged partial decryption` |
| Announced numbers are false, **even if a quorum of validators signs them** | Full recount: homomorphic totals, decryption proofs, discrete log | `detects a forged result even when validators re-sign the forgery` |

### 4.7 Availability (A1, A6)

| Threat | Defence | Residual |
|---|---|---|
| CPU exhaustion via the cast endpoint | Per-address throttling on writes; the board stays readable (`throttles the write path but never the bulletin board`) | Per-process, in-memory; not distributed |
| Scheduled proposer offline | View change to the next proposer | Coordinator-driven, no distributed timeout |
| More than *f* validators offline | Chain stalls (safety over liveness) | `cannot proceed when more than a third of validators are offline` |
| Lagging validator | Automatic resynchronisation; replayed blocks re-validated | `validates catch-up blocks rather than trusting the coordinator` |

---

## 5. Trust assumptions

These are what the guarantees rest on. If one fails, the listed property fails
with it.

1. **At most *k*−1 trustees collude** → otherwise secrecy fails for every voter.
2. **At most *f* validators are faulty, *n* > 3*f*** → otherwise the chain can fork
   or stall. Even then, a forged *result* is still caught by the recount.
3. **The validator set is obtained out of band.** A forger who controls a whole
   chain file can sign it with keys of their own. The verifier reports whether
   it used a pinned set (`--validators`) and warns when it did not.
4. **The voter checks an audit on an independent device** → otherwise
   cast-as-intended reduces to trusting the client.
5. **The published roll is scrutinised.** The commitment proves the roll used is
   the roll published; it does not prove the roll is *correct*.
6. **The browser bundle is the published one.** Its SHA-256 is published next to
   it (`dvoting-crypto.js.sha256`). Users who do not check it trust the server
   that delivered the code.
7. **The issuer key is distributed consistently.** An RA that gives each voter a
   different key could tag ballots. Clients pin the `keyId` sealed in block 0.
8. **The discrete-log assumption in RFC 3526 groups, and RSA, hold.** Neither is
   post-quantum.

---

## 6. Out of scope, stated plainly

| Not defended | Why | Where to go |
|---|---|---|
| **Coercion resistance** in the JCJ sense | Re-voting is mitigation only: a coercer watching the board sees that a credential voted again | Civitas-style fake credentials; [ledger notes](ledger-and-bulletin-board.md) |
| **Vote buying with a receipt** | The receipt proves inclusion, not content, which helps, but a buyer can watch the voter vote | Supervised polling stations |
| **Timing side channels** | BigInt arithmetic is not constant-time | Constant-time bignum library or HSM |
| **Network attackers on internal links** | Services speak plain HTTP and expect TLS termination at a proxy | TLS 1.3 / mTLS between services |
| **Identity proofing** | The roll is assumed correct; no KYC integration | CIPHER KYC or equivalent |
| **Key custody** | Keys are held in process memory / environment | KMS / HSM |
| **Post-quantum security** | Classical primitives throughout | Lattice-based schemes; see [literature review](literature-review.md) |
| **Distributed DoS** | Rate limiting is per process | WAF, distributed rate limiting |

---

## 7. How to check these claims yourself

```bash
npm test                     # every "Evidence" entry above is a test name
npm run demo                 # attacks attempted live and refused
npm run verify -- --help     # recount any election without trusting its servers
```
