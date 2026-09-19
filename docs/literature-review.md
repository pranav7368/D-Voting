# Literature Review — Cryptographically Verifiable, Blockchain-Audited Electronic Voting

A review of **20 recent papers (2021–2026)** covering the exact problem D-Voting
addresses: how to build a remote electronic election that is **end-to-end
verifiable (E2E-V)**, keeps ballots secret, and uses a distributed ledger
honestly — as tamper-evidence, not as the security mechanism.

Every entry below was located and its bibliographic details checked against the
publisher's own record (IACR ePrint, IEEE Xplore, Springer, PLOS, arXiv, ACM DL).
Where a claim is the *paper's own* claim rather than an independently replicated
result, it is written as such.

---

## 1. Scope and method

**Research question driving the review**

> For remote e-voting, which security properties can cryptography actually
> deliver, which ones does a blockchain deliver, and where does the literature
> say the boundary between the two lies?

| Item | Value |
|---|---|
| Period covered | 2021 – 2026 (17 of 20 papers are 2024 or later) |
| Sources searched | IACR ePrint Archive, IEEE Xplore, ACM DL, SpringerLink, PLOS ONE, Nature Scientific Reports, arXiv |
| Search terms | *end-to-end verifiable voting*, *homomorphic tally*, *threshold decryption*, *blind signature voting*, *coercion resistance*, *cast-as-intended*, *blockchain e-voting survey*, *post-quantum voting* |
| Inclusion criteria | (a) peer-reviewed venue **or** IACR/arXiv preprint with named authors and a full protocol; (b) makes a concrete security or performance claim; (c) topic overlaps at least one D-Voting subsystem |
| Exclusion criteria | Undergraduate-project papers with no threat model, papers that publish only a Solidity contract with no security argument, predatory-venue duplicates |
| Deliberate exception | [12] is included **because** it is weak — the review needs one representative of the large "put votes on a chain" genre it criticises |

**A note on honesty of sampling.** The blockchain-voting literature is heavily
skewed: hundreds of papers propose a chain and claim security, and a much smaller
number analyse whether the claim holds. This review deliberately over-samples the
analytical side, because that is where the useful design constraints are.

---

## 2. Master table — the 20 papers

| # | Authors (Year) | Title | Venue | Type | Core contribution |
|---|---|---|---|---|---|
| **A. Framing and critique** |
| 1 | Park, Specter, Narula, Rivest (2021) | Going from bad to worse: from Internet voting to blockchain voting | *Journal of Cybersecurity* 7(1), tyaa025 | Position / analysis | Argues blockchain voting **increases** the risk of undetectable, nation-scale failure; the field's most-cited counter-argument |
| 2 | Keeler, Smyth (2026) | Secrecy and Verifiability: An Introduction to Electronic Voting | arXiv:2602.12398 | Tutorial / formalisation | Game-based definitions of ballot secrecy and verifiability, written to be readable without a crypto background |
| **B. Systematic surveys** |
| 3 | Vladucu, Dong, Medina, Rojas-Cessa (2023) | E-Voting Meets Blockchain: A Survey | *IEEE Access* 11, pp. 23293–23308 | Survey | Taxonomy of blockchain e-voting by chain type, consensus and privacy primitive |
| 4 | Ohize, Onumanyi, Umar, Ajao, Isah, Dogo, Nuhu, Olaniyi, Ambafi, Sheidu, Ibrahim (2024) | Blockchain for securing electronic voting systems: a survey of architectures, trends, solutions, and challenges | *Cluster Computing* (Springer), DOI 10.1007/s10586-024-04709-8 | Survey | Architecture-level survey; catalogues open challenges (scalability, key management, identity) |
| 5 | Barelli, D'Onghia, Longari (2025) | Toward Secure Electronic Voting: A Survey on E-Voting Systems and Attacks | *IEEE Access* 13, pp. 89600–89626, DOI 10.1109/ACCESS.2025.3569334 | Survey | Surveys systems **and the attacks against them**; maps which properties each real system actually achieved |
| **C. Verifiability and privacy cryptography** |
| 6 | Pointcheval (2024) | Efficient Universally-Verifiable Electronic Voting with Everlasting Privacy | SCN 2024; IACR ePrint 2024/742 | Protocol | Linearly-homomorphic signatures give universal verifiability while ballot privacy becomes unconditional after the result is published |
| 7 | Bonte, Nicolas, Smart (2025) | Complex Elections via Threshold (Fully) Homomorphic Encryption | IACR ePrint 2025/1482 | Protocol + implementation | Extends homomorphic tallying past first-past-the-post to **Alternative Vote**, using threshold TFHE (`tfhe-rs`) |
| 8 | Kho, Heng, Tan, Chin (2025) | A provably secure coercion-resistant e-voting scheme with confidentiality, anonymity, unforgeability, and CAI verifiability | *PLOS ONE* 20(6), e0324182 | Protocol + proofs | Reconciles coercion-resistance with cast-as-intended verifiability at **linear** tally cost; argues anonymity implies CAI verifiability |
| 9 | Cortier, Debant, Esseiva, Gaudry, Høgåsen, Spadafora (2025) | A Practical and Fully Distributed E-Voting Protocol for the Swiss Context | IACR ePrint 2025/1625 | Protocol + formal analysis | Removes the trusted **offline** setup component; distributed setup, postal return codes, ProVerif-verified, linear setup and tally |
| **D. Blockchain systems engineering** |
| 10 | Stančíková, Homoliak (2023) | SBvote: Scalable Self-Tallying Blockchain-Based Voting | ACM SAC '23, DOI 10.1145/3555776.3578603 | System | Breaks the boardroom-scale ceiling of self-tallying voting; reports elections of up to ~1.5 M voters on Harmony |
| 11 | Wang, Guo, Liu, Li, Yuan (2024) | An efficient and versatile e-voting scheme on blockchain | *Cybersecurity* (Springer) 7, art. 62, DOI 10.1186/s42400-024-00226-8 | System | Aggregated **blind signatures** + NIZK authentication + threshold encryption; benchmarked on Hyperledger Fabric *and* Ethereum |
| 12 | Chouhan, Sharma (2025) | A New Era of Elections: Leveraging Blockchain for Fair and Transparent Voting | arXiv:2502.16127 | System (weak) | Immutable ledger + Aadhaar/biometric multi-factor identity. **Included as a critique specimen** — no ballot-secrecy mechanism, no verifiability argument |
| **E. Real deployments and empirical evidence** |
| 13 | Arafat (2025) | On the Estonian Internet Voting System, IVXV, SoK and Suggestions | IACR ePrint 2025/506 | SoK | Consolidates IVXV threats 2023–2025: re-voting attack, automated ballot stuffing, credential compromise, harvest-now-decrypt-later |
| 14 | Kraavi, Willemson (2025) | Proving vote correctness in the IVXV internet voting system | *Scientific Reports* 15, art. 31793, DOI 10.1038/s41598-025-16764-1 | Deployment engineering | Adds Bulletproofs-based ballot-validity proofs to a **live national system**; ~1.6 KB per proof, verifiable at the collector under peak load |
| 15 | Adida, Caron, Mirzaei, Teague (2024) | MERGE: Matching Electronic Results with Genuine Evidence for verifiable voting in person at remote locations | arXiv:2410.06705 | Hybrid protocol | Fast electronic return + paper evidence returned by mail, reconciled by risk-limiting audit |
| **F. Post-quantum migration** |
| 16 | Farzaliyev, Pärn, Saarse, Willemson (2025, online 2024) | Lattice-based zero-knowledge proofs in action: applications to electronic voting | *Journal of Cryptology* 38, art. 6, DOI 10.1007/s00145-024-09530-5 | Primitives + benchmarks | Lattice ZK proofs for ballot correctness, **homomorphic-tally** correctness, and cast-as-intended; compares homomorphic vs. mix-net costs |
| 17 | Hough, Sandsbråten, Silde (2025) | More Efficient Lattice-Based Electronic Voting from NTRU | *IACR Communications in Cryptology* 1(4) | Protocol + parameters | 5.3× smaller ciphertexts, 2.5× less communication, 2× faster than prior lattice voting; maps the NTRU overstretched regime |
| 18 | Bootle, Lyubashevsky, Merino-Gallardo (2025) | Efficient Verifiable Mixnets from Lattices, Revisited | PKC 2025, pp. 237–270; ePrint 2025/658 | Cryptanalysis + repair | Finds a **soundness-proof flaw** in prior lattice mixnets that propagated into later work, and repairs it |
| 19 | Srivastava, Roy, Mesnager, Kundu, Debnath, Mukhopadhyay (2025) | A Post-Quantum Secure End-to-End Verifiable E-Voting Protocol Based on Multivariate Polynomials | arXiv:2512.17613 | Protocol | First E2E-V voting protocol based on the **MQ** problem rather than lattices |
| 20 | Poudel, Poudel, Aryal, Nepal, Pathak, Subramaniyaswamy (2025) | A Quantum-Secure and Blockchain-Integrated E-Voting Framework with Identity Validation | arXiv:2511.16034 | System | Falcon signatures + face recognition with anti-spoofing + permissioned chain; <3.5 % spoof-detection error reported |

---

## 3. Property comparison matrix

The columns are the properties an election actually has to deliver. `✔` = argued
and supported in the paper, `◐` = partial or assumed, `✘` = not addressed,
`n/a` = out of scope for that paper type.

| # | Ballot secrecy mechanism | Cast-as-intended | Universal verifiability | Coercion resistance | Blockchain role | Post-quantum | Evaluated at scale |
|---|---|---|---|---|---|---|---|
| 1 | n/a (analysis) | n/a | n/a | n/a | **Argues against** security role | ✘ | n/a |
| 2 | Formal defs. | ◐ | ✔ (defined) | ✘ | none | ✘ | n/a |
| 3 | Survey | ◐ | ◐ | ◐ | Taxonomised | ◐ | n/a |
| 4 | Survey | ◐ | ◐ | ◐ | Central | ✘ | n/a |
| 5 | Survey + attacks | ✔ | ✔ | ◐ | Assessed critically | ◐ | n/a |
| 6 | Homomorphic enc. + **everlasting** privacy | ✘ | ✔ | ✘ | none | ✘ | ◐ |
| 7 | Threshold FHE (TFHE) | ✘ | ✔ | ✘ | none | ◐ (LWE-based) | ◐ (`tfhe-rs`) |
| 8 | Anonymous credentials + multi-sig | ✔ | ✔ | ✔ | none | ✘ | ✘ (analytic) |
| 9 | Distributed setup + return codes | ✔ | ✔ | ◐ | none | ✘ | ✔ (linear, Swiss reqs.) |
| 10 | Self-tallying, no authority | ✘ | ✔ | ✘ | **Bulletin board** | ✘ | ✔ (~1.5 M voters) |
| 11 | Blind signature + threshold enc. | ◐ | ✔ | ◐ | Ledger + smart contract | ✘ | ✔ (Fabric, Ethereum) |
| 12 | ✘ **none stated** | ✘ | ✘ | ✘ | Security mechanism (unjustified) | ✘ | ✘ |
| 13 | Deployed system review | ✔ | ✔ | ◐ | none | Flags HNDL risk | ✔ (national) |
| 14 | ElGamal + Bulletproofs | ✔ | ✔ | ◐ | none | ✘ | ✔ (national peak load) |
| 15 | Paper evidence | ✔ (paper) | ✔ (RLA) | ◐ | none | n/a | ◐ |
| 16 | Lattice homomorphic | ✔ | ✔ | ✘ | none | ✔ | ✔ (benchmarked) |
| 17 | NTRU / RLWE | ✘ | ✔ | ✘ | none | ✔ | ✔ (benchmarked) |
| 18 | Mix-net | ✘ | ✔ | ✘ | none | ✔ | ◐ |
| 19 | MQ-based | ✔ | ✔ | ✘ | none | ✔ | ✘ |
| 20 | ◐ (chain storage) | ✘ | ✘ | ✘ | Storage + tamper-evidence | ✔ (Falcon) | ◐ |

**The single clearest reading of this table:** *no paper fills every column.*
Coercion resistance (col. 4) is achieved by exactly one protocol paper [8], and
post-quantum security (col. 6) never co-occurs with it. That is the shape of the
open problem.

---

## 4. Thematic review

### 4.1 The framing question: what is the blockchain actually for?

**[1] Park, Specter, Narula & Rivest (2021)** is the paper every project in this
area has to answer. Their argument is not that blockchains are broken; it is
that voting has a property most applications do not — a *secret ballot* means
you cannot let voters detect fraud by checking their own records against a
public log without also letting a coercer check. They show that Internet and
blockchain voting introduce failure modes that are **undetectable and
nation-scale**: a compromised client cannot be caught by the ledger, because the
ledger faithfully records exactly what the compromised client submitted.
Consensus protects the *log*, not the *inputs*.

The critique is sharpened by **[5] Barelli et al. (2025)**, which is the most
useful survey in this set precisely because it surveys attacks alongside
systems. Where earlier surveys tabulate claimed properties, [5] tabulates what
happened when the systems met adversaries.

**[2] Keeler & Smyth (2026)** supplies the vocabulary. Their game-based
definitions of ballot secrecy and verifiability let you say *precisely* what a
scheme achieves, instead of the property-checklist style that makes so much of
this literature incomparable. For a class presentation this is the right
reference to cite when defining terms.

> **Design consequence.** The literature does not support "blockchain =
> secure voting". It supports a narrower and defensible claim: a ledger is a
> good **append-only, publicly auditable bulletin board**, and the security of
> the ballot must come from cryptography that holds *even if the ledger operator
> is dishonest*.

### 4.2 Surveys: what the field looks like in aggregate

| Survey | Coverage angle | Named open problems |
|---|---|---|
| [3] Vladucu et al. (2023) | Chain type, consensus, privacy primitive | Privacy vs. transparency tension; scalability of on-chain crypto |
| [4] Ohize et al. (2024) | Architectures and deployment trends | Scalability, key management, identity binding, legal acceptance |
| [5] Barelli et al. (2025) | Systems **and** attacks | Client-side compromise; gap between claimed and demonstrated properties |

The three surveys converge on the same four unresolved issues — **voter identity
binding, client-side (device) trust, scalability of on-chain verification, and
key management for the tallying authorities**. Notably, none of the three
identifies "immutability" as an unresolved problem, which reinforces §4.1: the
ledger is the easy part.

### 4.3 Verifiability and privacy: where the real progress is

This is the strongest cluster in the review.

**[6] Pointcheval (2024)** attacks the most uncomfortable property in the field:
today's encrypted ballots, sitting on a public bulletin board, are only private
for as long as the underlying assumption holds. *Everlasting privacy* means that
once the result is published, the published transcript reveals nothing about
individual ballots even to an unbounded adversary. He obtains it using
linearly-homomorphic signatures to carry verifiability, with security in the
algebraic group and random oracle models.

**[7] Bonte, Nicolas & Smart (2025)** answer a limitation that constrains almost
every homomorphic-tally system, including D-Voting: additive homomorphism gives
you *counts*, so you get first-past-the-post cleanly and preferential systems
badly. Using threshold TFHE they run **Alternative Vote** — a genuinely complex
electoral system — entirely under encryption, with an implementation on
`tfhe-rs`. The cost is FHE-scale computation, so this is a capability result
rather than a drop-in replacement for exponential ElGamal.

**[8] Kho, Heng, Tan & Chin (2025)** take on the field's sharpest tension.
Cast-as-intended verifiability wants the voter to be able to *check* their
ballot; coercion resistance wants them to be *unable to prove* anything about it.
Building on Finogina & Herranz (2023), they achieve both with confidentiality,
anonymity, unforgeability and double-voting prevention, and — importantly for
practicality — **linear** tally complexity, escaping the quadratic cost of the
classic JCJ construction.

**[9] Cortier et al. (2025)** is the most operationally relevant paper here.
Swiss federal requirements are the strictest published in the world, and the
authors' contribution is to remove the trusted **offline** setup component that
previous compliant systems relied on: the voting material is generated by
several parties in a distributed way, individual verifiability comes from
postally-delivered return codes, and the whole thing is machine-checked in
ProVerif with linear setup and tally. This is the paper that shows a
"no-single-trusted-party" setup is deployable, not just provable.

> **Design consequence.** Distributed trust at *setup* (not just at tallying) is
> now the state of the art. A system where a single machine ever holds the whole
> election private key is behind the literature — which is the argument for
> Pedersen DKG over dealer-based key sharing.

### 4.4 Blockchain systems engineering: scale and cost

**[10] SBvote (Stančíková & Homoliak, 2023)** addresses the embarrassment of
self-tallying voting: the Open Vote Network and its successors are
cryptographically elegant and cap out around boardroom size because every
computation happens in the contract. SBvote restructures this and reports
elections up to roughly **1.5 million voters** on Harmony. The trade-off is
worth stating plainly in a presentation: self-tallying removes the tallying
authority entirely, but requires *every voter to participate in a second round*,
which is a poor fit for a public election where turnout is partial.

**[11] Wang et al. (2024)** is the closest published architecture to D-Voting:
smart-contract-based **aggregated blind signatures** for voter privacy,
non-interactive zero-knowledge proofs for authentication, and **threshold
encryption** so no ballot can be read early. They benchmark on both Hyperledger
Fabric and Ethereum and report faster ballot submission and lower storage than
comparable schemes. The main critique is that "eight fundamental voting criteria"
is a checklist argument rather than the game-based treatment [2] advocates.

**[12] Chouhan & Sharma (2025)** is included as the specimen. It proposes an
immutable ledger plus multi-factor identity (Aadhaar, driver's licence,
biometrics, picture-pattern) and concludes that impersonation risk is
substantially reduced. The identity work is real, but the paper states **no
ballot-secrecy mechanism and no verifiability argument** — if votes are recorded
on a ledger alongside authenticated identities, the default outcome is a
permanently public record of who voted for whom. It is a clean illustration of
exactly the failure [1] predicted, and it is far more representative of the
genre than [6]–[9] are.

### 4.5 What deployment teaches that protocols do not

**[13] Arafat (2025)** consolidates the Estonian IVXV picture across 2023–2025.
The catalogue is sobering and none of it is a break of the underlying
cryptography: a re-voting attack, ballot stuffing through automation, gaps in
voter-application authentication, credential-compromise exposure from a
permissive architecture, and harvest-now-decrypt-later risk on stored ballots.

**[14] Kraavi & Willemson (2025)** documents the fix for a specific, real
failure: during the 2024 European Parliament elections an **incorrect ballot
reached the decryption phase for the first time**. Their response is to add
zero-knowledge proofs of ballot validity — Bulletproofs, with a group-switching
technique to bridge IVXV's ElGamal to elliptic-curve range proofs — with proofs
of about **1.6 KB**, verifiable at the collection server under peak load. The
significance for a student project is direct: *ballot-validity proofs are not an
academic luxury; a national system was hurt by not having them.*

**[15] MERGE (Adida, Caron, Mirzaei & Teague, 2024)** is the honest hedge.
For overseas and military voters it combines fast electronic return with paper
evidence returned by mail, reconciled by risk-limiting audit. It concedes what
[1] argues: without software independence, an all-electronic return has no
recovery path. Anyone claiming a purely digital election should be able to say
why they are not doing this.

### 4.6 Post-quantum: the migration is already underway

| Paper | Assumption | What it delivers | Maturity |
|---|---|---|---|
| [16] Farzaliyev et al. | Lattice (RLWE) | ZK proofs of ballot correctness, homomorphic-tally correctness, cast-as-intended | Benchmarked primitives |
| [17] Hough, Sandsbråten & Silde | NTRU + RLWE | 5.3× smaller ciphertexts, 2.5× less communication, 2× faster | Concrete parameters |
| [18] Bootle, Lyubashevsky & Merino-Gallardo | Lattice | **Repairs a soundness-proof flaw** in prior mixnets | Cryptanalysis |
| [19] Srivastava et al. | Multivariate (MQ) | First MQ-based E2E-V protocol | Early / preprint |
| [20] Poudel et al. | Falcon + biometrics | Deployable-style framework, permissioned chain | Prototype |

Two things stand out. First, **[16] is the paper most directly transferable to a
Helios-style design**, because it supplies drop-in post-quantum replacements for
precisely the three proofs such systems use — validity, tally correctness, and
cast-as-intended — and benchmarks homomorphic tallying against mix-nets rather
than assuming one. Second, **[18] is a caution**: a soundness-proof error in a
respected lattice mixnet propagated into subsequent adaptations before being
caught. New post-quantum machinery is not yet as settled as the discrete-log
constructions it will replace, and [13]'s harvest-now-decrypt-later concern is
the reason the migration cannot simply be deferred either.

---

## 5. Synthesis — six findings

| # | Finding | Supported by |
|---|---|---|
| F1 | A blockchain provides tamper-evidence and public auditability, **not** ballot integrity or secrecy. Treating it as the security mechanism creates undetectable, large-scale failure modes. | [1], [5], and negatively by [12] |
| F2 | The state of the art has moved from *distributed tallying* to **distributed setup** — no single party should ever hold the election key, even before voting opens. | [9], [8] |
| F3 | Client-side (voting-device) compromise is the field's least-solved problem. Cast-as-intended verification, return codes, and paper evidence are the three known answers. | [8], [9], [14], [15] |
| F4 | Ballot-validity zero-knowledge proofs are operationally necessary, not decorative — a national system was materially harmed by their absence. | [14], [16] |
| F5 | Coercion resistance is now achievable at **linear** cost, removing the classic JCJ objection; but it still does not co-exist with post-quantum security in any single published protocol. | [8] vs. [16]–[20] |
| F6 | Scalability is solved for ledger throughput and unsolved for on-chain cryptographic verification; the working pattern is verify off-chain, commit succinctly on-chain. | [10], [11] |

### Research gaps

| Gap | Why it is open | Nearest work |
|---|---|---|
| G1 | Coercion resistance **and** post-quantum security in one protocol | [8] + [16] have never been combined |
| G2 | Everlasting privacy in a *deployed* system | [6] is theory only; deployed systems [13],[14] have none |
| G3 | Complex electoral systems (STV/AV) at national cost | [7] shows feasibility, at FHE cost |
| G4 | Formal, machine-checked analysis of blockchain-based schemes | [9] does this with ProVerif — for a non-blockchain protocol; blockchain papers rarely do |
| G5 | Eligibility fraud by a dishonest roll authority | No cryptographic answer exists in any of the 20; all rely on procedural roll publication |

---

## 6. Positioning: how D-Voting sits against this literature

| D-Voting design decision | Literature it follows | Literature it does **not** yet satisfy |
|---|---|---|
| Ledger is an **audit layer**, cryptography carries the guarantees | Directly implements the conclusion of [1], [5] | — |
| Exponential ElGamal + homomorphic tally, ballots never decrypted | Standard across [6], [14], [16] | Cannot express preferential voting — [7] |
| Disjunctive Chaum-Pedersen ballot-validity proofs, strong Fiat-Shamir | Exactly the failure [14] had to retrofit into IVXV | — |
| **Pedersen DKG** — the election key is never assembled | Matches the distributed-setup advance in [9] | — |
| Shamir *k*-of-*n* threshold decryption with per-trustee proofs | Standard [6], [11]; validated operationally in [13] | — |
| RSA blind signatures (RFC 9474) for unlinkable credentials | Same primitive family as [11] | Blind signatures alone give anonymity, not coercion resistance — [8] |
| Benaloh cast-or-audit challenge | One of the three known answers to device compromise (F3) | Return codes [9] and paper evidence [15] are the alternatives not taken |
| Permissioned PoA ledger with RFC 6962 Merkle inclusion proofs | Bulletin-board role endorsed by [3], [10] | — |
| Voter re-voting to blunt coercion | Partial mitigation | Not coercion-resistant in the [8] sense; and [13] documents a re-voting **attack** on IVXV |
| Discrete-log cryptography throughout | Current practice | Not post-quantum — [16]–[20]; [13]'s harvest-now-decrypt-later applies |

**Honest limitations to state in the presentation**, each backed by a citation:

1. **Not coercion-resistant.** Re-voting is a mitigation, not the property
   defined in [8] — and [13] shows re-voting itself has been attacked.
2. **Not post-quantum.** Ballots posted today are exposed to
   harvest-now-decrypt-later [13]; the migration path is [16].
3. **No everlasting privacy.** Encrypted ballots stay on the chain forever, and
   their secrecy rests on a computational assumption [6].
4. **Eligibility depends on the roll, not on cryptography.** This is gap G5 —
   the project's own README states it, and no paper in this review solves it.
5. **First-past-the-post only.** Preferential counting needs [7]'s machinery.
6. **Device trust rests on cast-or-audit alone.** [9] and [15] show two other
   defences that a production system would likely combine.

Stating these is a strength, not a weakness: [5] and [13] exist precisely because
so many systems claimed properties they had not established.

---

## 7. Presentation plan

| Slide | Content | Papers to cite |
|---|---|---|
| 1 | Title, the research question | — |
| 2 | Why e-voting is hard: secrecy **vs.** verifiability | [2] |
| 3 | The critique that frames everything | [1] |
| 4 | Survey landscape — four recurring open problems | [3], [4], [5] |
| 5 | Master table (§2) | all 20 |
| 6 | Property matrix (§3) — "nobody fills every column" | all 20 |
| 7 | Where the progress is: distributed setup, coercion resistance, everlasting privacy | [6], [8], [9] |
| 8 | What deployment taught us: IVXV's incorrect ballot | [13], [14] |
| 9 | Blockchain engineering: scale and its price | [10], [11], and [12] as the counter-example |
| 10 | Post-quantum: ready primitives, unsettled proofs | [16], [17], [18] |
| 11 | Six findings + five gaps (§5) | — |
| 12 | Where D-Voting sits, limitations stated openly (§6) | — |

**Likely questions, and the answer**

| Question | Answer |
|---|---|
| "Why blockchain at all, if [1] says it makes things worse?" | Because we use it for the role [1] does *not* object to — an append-only, publicly auditable bulletin board. Ballot integrity comes from the ZK proofs and threshold decryption, which hold even if every validator is dishonest. |
| "Can a voter prove how they voted?" | They can prove their ballot was *counted* (Merkle inclusion), not *what it said*. That gap is deliberate; closing it would enable vote-selling. Full coercion resistance in the sense of [8] is future work. |
| "What about quantum computers?" | Not addressed today. [13] names the exact risk (harvest-now-decrypt-later) and [16] is the migration path, since it replaces precisely the three proofs we use. |
| "What stops the commission from inventing voters?" | Nothing cryptographic — that is gap G5, and no paper in this review solves it. The defence is procedural: freeze the roll, hash it, commit the digest on-chain, publish it. |
| "Is this better than the papers you reviewed?" | No — it implements the consensus design of [1], [9], [11] and [14] as a working system. Its contribution is integration and honest scoping, not a new primitive. |

---

## 8. References

1. S. Park, M. Specter, N. Narula, and R. L. Rivest, "Going from bad to worse: from Internet voting to blockchain voting," *Journal of Cybersecurity*, vol. 7, no. 1, tyaa025, 2021. https://academic.oup.com/cybersecurity/article/7/1/tyaa025/6137886
2. P. Keeler and B. Smyth, "Secrecy and Verifiability: An Introduction to Electronic Voting," arXiv:2602.12398, Feb. 2026. https://arxiv.org/abs/2602.12398
3. M. V. Vladucu, Z. Dong, J. Medina, and R. Rojas-Cessa, "E-Voting Meets Blockchain: A Survey," *IEEE Access*, vol. 11, pp. 23293–23308, 2023. https://ieeexplore.ieee.org/document/10061373/
4. H. O. Ohize *et al.*, "Blockchain for securing electronic voting systems: a survey of architectures, trends, solutions, and challenges," *Cluster Computing*, 2024, doi:10.1007/s10586-024-04709-8. https://dl.acm.org/doi/10.1007/s10586-024-04709-8
5. D. Barelli, M. D'Onghia, and S. Longari, "Toward Secure Electronic Voting: A Survey on E-Voting Systems and Attacks," *IEEE Access*, vol. 13, pp. 89600–89626, 2025, doi:10.1109/ACCESS.2025.3569334. https://ieeexplore.ieee.org/document/11002499/
6. D. Pointcheval, "Efficient Universally-Verifiable Electronic Voting with Everlasting Privacy," in *SCN 2024*; IACR ePrint 2024/742. https://eprint.iacr.org/2024/742
7. C. Bonte, G. Nicolas, and N. P. Smart, "Complex Elections via Threshold (Fully) Homomorphic Encryption," IACR ePrint 2025/1482, 2025. https://eprint.iacr.org/2025/1482
8. Y.-X. Kho, S.-H. Heng, S.-Y. Tan, and J.-J. Chin, "A provably secure coercion-resistant e-voting scheme with confidentiality, anonymity, unforgeability, and CAI verifiability," *PLOS ONE*, vol. 20, no. 6, e0324182, 2025, doi:10.1371/journal.pone.0324182. https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0324182
9. V. Cortier, A. Debant, O. Esseiva, P. Gaudry, A. Høgåsen, and C. Spadafora, "A Practical and Fully Distributed E-Voting Protocol for the Swiss Context," IACR ePrint 2025/1625, 2025. https://eprint.iacr.org/2025/1625
10. I. Stančíková and I. Homoliak, "SBvote: Scalable Self-Tallying Blockchain-Based Voting," in *Proc. 38th ACM/SIGAPP Symp. on Applied Computing (SAC '23)*, Tallinn, Estonia, 2023, doi:10.1145/3555776.3578603. https://dl.acm.org/doi/10.1145/3555776.3578603
11. B. Wang, F. Guo, Y. Liu, B. Li, and Y. Yuan, "An efficient and versatile e-voting scheme on blockchain," *Cybersecurity*, vol. 7, art. 62, 2024, doi:10.1186/s42400-024-00226-8. https://link.springer.com/article/10.1186/s42400-024-00226-8
12. S. Chouhan and G. Sharma, "A New Era of Elections: Leveraging Blockchain for Fair and Transparent Voting," arXiv:2502.16127, Feb. 2025. https://arxiv.org/abs/2502.16127
13. S. M. Arafat, "On the Estonian Internet Voting System, IVXV, SoK and Suggestions," IACR ePrint 2025/506, 2025. https://eprint.iacr.org/2025/506
14. T. Kraavi and J. Willemson, "Proving vote correctness in the IVXV internet voting system," *Scientific Reports*, vol. 15, art. 31793, 2025, doi:10.1038/s41598-025-16764-1. https://www.nature.com/articles/s41598-025-16764-1
15. B. Adida, J. Caron, A. Mirzaei, and V. Teague, "MERGE: Matching Electronic Results with Genuine Evidence for verifiable voting in person at remote locations," arXiv:2410.06705, Oct. 2024. https://arxiv.org/abs/2410.06705
16. V. Farzaliyev, C. Pärn, H. Saarse, and J. Willemson, "Lattice-based zero-knowledge proofs in action: applications to electronic voting," *Journal of Cryptology*, vol. 38, art. 6, 2025 (online 2024), doi:10.1007/s00145-024-09530-5. https://link.springer.com/article/10.1007/s00145-024-09530-5
17. P. Hough, C. Sandsbråten, and T. Silde, "More Efficient Lattice-Based Electronic Voting from NTRU," *IACR Communications in Cryptology*, vol. 1, no. 4, 2025. https://cic.iacr.org/p/1/4/10
18. J. Bootle, V. Lyubashevsky, and A. Merino-Gallardo, "Efficient Verifiable Mixnets from Lattices, Revisited," in *Public-Key Cryptography — PKC 2025*, pp. 237–270; IACR ePrint 2025/658. https://eprint.iacr.org/2025/658
19. V. Srivastava, D. Roy, S. Mesnager, N. Kundu, S. K. Debnath, and S. Mukhopadhyay, "A Post-Quantum Secure End-to-End Verifiable E-Voting Protocol Based on Multivariate Polynomials," arXiv:2512.17613, Dec. 2025. https://arxiv.org/abs/2512.17613
20. A. Poudel, U. Poudel, D. Aryal, A. Nepal, P. Pathak, and V. Subramaniyaswamy, "A Quantum-Secure and Blockchain-Integrated E-Voting Framework with Identity Validation," arXiv:2511.16034, Nov. 2025. https://arxiv.org/abs/2511.16034

**Also referenced in discussion (not counted among the 20):**
A. Juels, D. Catalano, and M. Jakobsson, "Coercion-Resistant Electronic Elections," WPES 2005 — origin of the coercion-resistance definition and the quadratic-tally problem [8] resolves.
P. McCorry, S. F. Shahandashti, and F. Hao, "A Smart Contract for Boardroom Voting with Maximum Voter Privacy," FC 2017 — the Open Vote Network that [10] scales.
S. Finogina and J. Herranz, "Coercion-Resistant Cast-as-Intended Verifiability for Computationally Limited Voters," FC 2023 Workshops — the construction [8] builds on.

---

*Compiled 11 August 2026. Bibliographic details verified against publisher records; performance figures are as reported by the respective authors.*
