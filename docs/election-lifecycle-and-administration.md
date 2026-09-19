# The election's life, and what an administrator can do

A real election commission has real powers. It decides who stands, who is on the
roll, and when the poll opens and closes. A system that pretended otherwise
would not be a voting system; it would be a cryptography demonstration with a
voting theme.

So those powers are here, in a console at `/admin`. The question this document
answers is the one that follows immediately: **if the commission can do all
that, what stops it rigging the election?**

The answer is in three parts, and only one of them is cryptography.

---

## 1. The shape of the problem

Two requirements that look compatible until you build them:

1. *Only eligible people vote, and each of them once.* Enforcing this means
   knowing who someone is.
2. *Nobody ever learns how anyone voted.* Preserving this means not knowing.

If one system checks eligibility **and** receives the ballot, it holds both
halves. Encrypting the ballot does not help: whoever can decrypt it can also
read the row next to it saying which voter it came from. And unlike a paper
system, the link is written down — five years later somebody can still read it.

The resolution is the one a polling station already uses. The officer checks your
identity, marks the register, and hands you a **blank ballot paper**. Behind the
curtain nobody is watching. The officer knows *you attended*; the box knows *a
vote was cast*; nobody knows which vote was yours.

This system does the same with two services and a blind signature:

| | Sees | Never sees |
|---|---|---|
| **Registration Authority** | your roll id, your enrolment code | your credential, your ballot |
| **Ballot box** | an anonymous credential, an encrypted ballot | who you are |

The Registration Authority signs a credential **it cannot read** — the voter's
browser blinds it first. Later the ballot box can check that signature and be
certain the holder was entitled to one, while the RA cannot match it to anything
it has ever seen. The unlinkability is information-theoretic: an adversary
holding the RA's private key, with unbounded computing power, still cannot
recover the link, because the information was never there.

That is why the voter's browser calls the RA **directly** and never through the
ballot box. Proxying the first through the second would let one party observe
both ends and correlate them by session or timing — reconstructing exactly the
link the blind signature exists to destroy. See
[registration-and-blind-signatures.md](registration-and-blind-signatures.md).

**Voting once, without knowing who you are**, then falls out of two independent
locks: the RA issues one credential per roll entry, and the ballot box accepts
each credential once. Neither party knows both facts, and together they enforce
exactly-once.

---

## 2. What the administrator can and cannot do

| Can | Cannot |
|---|---|
| Add voters to the roll | Learn who voted, or whether a particular person voted |
| Revoke a roll entry | Delete a roll entry from the committed record |
| Set the candidates and selection limits | Change any of them once the poll is open |
| Set the opening and closing times | Extend a poll past a closing time already sealed |
| Open the poll | Reopen a closed one — including by restarting the service |
| Close the poll, seal blocks | Decrypt anything, or see a running total |
| Watch the ceremony | Contribute a trustee's share, or hurry one |

The bottom two rows are structural rather than enforced. The ballot box holds no
trustee key shares and no validator signing keys, so there is no code path from
the console to a plaintext vote or to a forged block. `admin.ts` has no route
that returns a ballot because none can be written.

### Sealing the configuration

Until it is opened, an election is a **draft** living in one process. Opening it
writes block 0:

```jsonc
{
  "electionId":         "…",
  "candidates":         ["…"],
  "minSelections":      1,
  "maxSelections":      1,
  "group":              "modp3072",
  "issuerKeyId":        "…",   // which authority confers eligibility
  "electionPublicKey":  "…",   // which key ballots are encrypted to
  "trustees":           { "threshold": 3, "total": 5, "publicShares": [ … ] },
  "validators":         [ … ], "quorum": 3,
  "rollCommitment":     "…",   // section 3
  "opensAt": null, "closesAt": null, "sealedAt": "…"
}
```

That block carries the same validator quorum as every other, so it is as
tamper-evident as the ballots. From then on:

- every editing route refuses;
- ballots are verified against the **sealed** candidate list, so a ballot can
  only ever be valid for the race that was committed before voting began;
- the service **refuses to start** if its own configuration disagrees with the
  sealed one on the cryptographic fields. If the chain says one issuer key and
  the process was configured with another, exactly one of them is wrong, and
  there is no safe way to guess which. Starting anyway would mean accepting
  credentials from an authority the election never recognised.

Note which fields are which. Candidates and schedule are **adopted** from the
chain, because the chain is what voters were shown. Keys, validators and quorum
must **match**, because a mismatch there is never benign.

### Closing

Closing writes a second entry, in the same block as any ballot still waiting to
be sealed. Two things follow, and both are the reason it is done this way:

- a ballot accepted seconds before the deadline cannot be stranded outside the
  record;
- "voting has ended" survives a restart.

That second point was a real bug, not a hypothetical. The close used to be a
boolean in memory, which meant any restart — a crash, a deploy, or a deliberate
one — silently reopened a closed election. The console promised something the
implementation did not deliver. It is now a fact on the chain, and a test
restarts the whole cluster to prove it.

A **closing time** is enforced the same way: the phase is computed from the
chain plus the clock, never stored. An election whose `closesAt` has passed is
closed whether or not anyone pressed a button, because a deadline that only
takes effect if an operator remembers to act is not a deadline.

---

## 3. Adding voters: the attack cryptography cannot stop

Everything above makes cheating detectable. Adding voters is the exception, and
it is the most important paragraph in this document.

**A fabricated roll entry produces a cryptographically perfect ballot.** It has a
valid credential, valid validity proofs, and a valid place in the tally. No
proof anywhere in the protocol distinguishes it from a real one, because
eligibility is a claim about the world, and the world is not verifiable by
hashing it. A commission that quietly inserts a thousand names gets a thousand
votes, and every cryptographic check still passes.

Real elections do not solve this with mathematics either. They publish the roll,
and give parties and citizens a window to object. The defence is transparency and
the fact that fabrication at scale is noticeable.

What cryptography can add is a way to make the **published** roll and the **used**
roll provably the same one:

1. The commission enrols voters. Enrolment codes are returned **once** — the
   service stores only an HMAC under a server-held pepper, so a database dump
   yields no usable code and a lost card means a new entry, not a reprint.
2. The commission **freezes** the roll. One-way: additions are refused from then
   on, because the digest of a roll that can still change proves nothing.
3. Freezing produces a commitment, which is sealed into block 0 when the poll
   opens.
4. The commission **publishes** the roll identifiers. Anyone can recompute the
   digest and compare it with the chain.

The commitment covers the roll identifiers only — sorted and length-prefixed, so
it does not depend on insertion order and entries cannot be reshaped to collide.
Deliberately **not** the enrolment-code hashes: a commitment that included
secrets could only be checked by the party holding them, and a commitment nobody
outside the commission can verify is decoration.

Revocation is recorded, never erased. A revoked entry stays on the roll and
therefore inside the commitment; only its ability to authenticate is removed.
Deleting it would silently change the digest the election was opened with.

So the honest claim is not *"the commission cannot cheat"*. It is:

> **The commission can cheat, but it cannot cheat invisibly.**

That is what tamper-evidence means, and it is the whole reason there is a chain
at all.

---

## 4. Why the count needs several people

The commission runs the election. It does not hold the key that opens the result.

The election key is generated by **Pedersen distributed key generation** — no
dealer, no moment at which any machine holds the whole private key (see
[threshold-key-generation.md](threshold-key-generation.md)). Each trustee ends up
with one Shamir share and publishes the matching public share, which is sealed
into block 0 alongside everything else.

After the poll closes, the ballot box computes the encrypted per-candidate
totals from the chain and publishes them. Each trustee then, on their own
machine:

1. downloads the bulletin board and **re-verifies every block** against the
   validator quorum;
2. checks that the candidate list and its own public share match the sealed
   roster;
3. confirms the close record is on the chain;
4. **recomputes the encrypted totals from the ballots itself** and compares them
   with what it was asked to decrypt;
5. only then applies its share, and proves in zero knowledge that it used the
   share it committed to at setup.

Step 4 is what makes a trustee something other than a rubber stamp. A ballot box
that inflated a total or dropped an inconvenient ballot produces different
ciphertexts, and the trustee stops rather than lending its share to the wrong
number. Five trustees who decrypt whatever they are handed are worth no more
than one.

Step 5 is what makes a *dishonest trustee* detectable. A trustee that submits a
random group element instead of `alpha^{x_i}` corrupts the tally, and because the
result is decrypted only once there is nothing to compare it against. The
Chaum-Pedersen proof binds the partial decryption to that trustee's published
share, so a bad submission is rejected immediately and **names its own author**.

The submission endpoint has no token, and that is not an oversight: only the
holder of share *i* can produce a proof that verifies against public share *i*. A
bearer token would add a secret to steal without adding a guarantee.

When *k* valid shares have arrived, the ballot box combines them, decrypts the
totals, and seals the result — with every partial decryption and every proof —
onto the chain. Anyone can then recount it from that record alone.

---

## 5. Known limitations, stated honestly

**Adding voters is not detectable by the protocol.** Section 3 above. The
commitment makes an addition *after the freeze* impossible to hide; it says
nothing about whether the roll was honest when it was frozen. Committing to a
roll full of invented names commits to fraud, faithfully. This is the single
largest residual risk in the system and no amount of cryptography closes it —
only publication, objection windows, and the ordinary politics of scrutiny.

**Threshold trust is real trust.** Any *k* colluding trustees can decrypt
individual ballots, not just totals. The protection is that they are supposed to
be organisations with opposing interests; if the commission appoints five
trustees it controls, the threshold is decorative. Choosing them is a political
act that the software cannot check.

**The administrator is a single bearer token.** The audit log records what was
done, not who did it, and there is no two-person rule on irreversible actions.
A real deployment wants named operators and dual control on open, close and roll
changes.

**The operator audit log is in memory and bounded.** It is operational
accountability rather than part of the election record, and it does not survive a
restart. Production should ship it to write-once storage. It is deliberately not
on the chain: operator activity on a public board leaks the rhythm of the count.

**Ceremony state is in memory.** If the ballot box restarts mid-ceremony,
trustees who had already submitted must submit again. Harmless — a partial
decryption is deterministic evidence, not a one-shot action — but worth knowing
before a demo.

**The commission runs the servers.** In this deployment it hosts the ballot box
and serves the voter's JavaScript. The bundle's SHA-256 is published and the
build refuses to ship server-only key material, but nothing forces a browser to
check it. Subresource integrity and an independently hosted verifier would close
this; today it rests on the cast-or-audit challenge catching a lying client.

**Timing still links.** Blind signatures destroy the *content* link between
registration and voting. They do nothing about the *temporal* one: an observer
with both services' logs sees a registration at 10:31:04 and a ballot at
10:31:09. Separating the credential-issuance window from the voting window, or
mixing submissions, would address it. Neither is implemented.

**Re-voting is coercion mitigation, not coercion resistance.** A voter under
duress can comply and re-vote later, and only the last ballot counts. But ballots
are grouped by credential fingerprint on a public board, so a coercer can see
that *a* later ballot was cast — not its content, but the fact. Genuine coercion
resistance needs fake credentials indistinguishable from real ones
(Juels-Catalano-Jakobsson, as in Civitas) and is not implemented here.
