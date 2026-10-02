# Demo Script

A timed walkthrough for presenting D-Voting, about 12 minutes. Each step says
what to run, what the audience will see, and the one sentence that explains why
it matters. Rehearse once on the presenting machine. Every command here was run
on a clean checkout.

**Before you start** (do this before the audience arrives):

```bash
npm install
npm run build:web
npm test            # confirm green on this machine; takes about a minute
```

Have three terminal windows and one browser ready.

---

## Part 1: The whole protocol in one run (3 min)

```bash
npm run demo
```

| Watch for | Say |
|---|---|
| Voters registering with blind-signed credentials | "The Registration Authority signs a credential it cannot see, so even it cannot link a voter to a ballot." |
| **A malicious voting app caught** by cast-or-audit | "The app commits to a ballot before it knows whether it will be audited. A cheating app gets caught with high probability." |
| Fraud attempts refused (double vote, inflated vote, replay) | "Every ballot carries zero-knowledge proofs, so a ballot with five votes for one candidate is rejected without being decrypted." |
| A coerced voter re-voting | "Only the last ballot per credential counts. This mitigates coercion; it is not full coercion resistance, and the threat model says so." |
| Homomorphic tally, 3-of-5 threshold decryption | "No individual ballot is ever decrypted. Only the totals are, and only when three independent trustees agree." |
| **Tampering with the ledger, detected** | "Change one byte of history and every observer can see it." |

---

## Part 2: A real election, run by hand (6 min)

**Terminal 1:**

```bash
npm run dev
```

This starts eleven processes: four validators, five trustees, the Registration
Authority and the ballot box. Keep the printed tokens visible.

> "Each of these would be a different organisation on different hardware. Here
> they share one laptop, but none of them shares a key."

### 2a. Open the election: `http://localhost:8082/admin`

1. Paste the **commission token** and the **roll token**. "Two tokens because
   they are two authorities."
2. Set three candidates.
3. Freeze the roll. "That produces a hash of the roll, which is sealed onto the
   chain. Adding a voter later changes the hash."
4. Open the poll. Then try to edit a candidate and show the refusal. "The
   definition is in block 0. Nobody can change it now, including me."

### 2b. Vote: `http://localhost:8082/vote`

Use a card from `.local/cards.csv`.

1. Choose a candidate, then press **Check** instead of Cast. "I'm auditing the
   app: it has to prove it encrypted what I chose. That ballot is now spoiled."
2. Prepare again and **Cast**. Copy the tracking code.
3. Open the tracking link (`/verify`). "My browser re-checks the signatures and
   the Merkle path itself. It doesn't trust the server's answer."

Cast two or three more ballots with other cards so the count is interesting.

### 2c. Close and count

1. `/admin`, then **Close**. "Closing is written to the chain, so a restart
   cannot reopen it."
2. Open any **three** trustee consoles (ports 8100–8104, each with its own
   token), then press *Verify and contribute my share*. Read out the checks each
   trustee lists. "Each trustee downloads the chain and adds up the ballots itself
   before it agrees to decrypt."
3. `http://localhost:8082/results`: the result and the server-side recount.

---

## Part 3: Recount without trusting anyone (2 min)

**Terminal 2:**

```bash
npm run verify -- --url http://localhost:8082 \
  --validators .local/validators.json --save .local/board.json
```

> "This is a standalone verifier. It trusts only the validator keys I obtained
> separately. It re-checks every block, every ballot proof, every trustee's
> decryption proof, and recomputes the result."

Add your tracking code to prove inclusion: `--ballot <tracking-code>`.

Now **stop everything** (Ctrl+C in Terminal 1) and run:

```bash
npm run verify -- --file .local/board.json --validators .local/validators.json
```

> "Every server is off. The election can still be verified, today or in ten
> years, by anyone with this file."

---

## Part 4: Close with the limits (1 min)

Open [docs/threat-model.md](docs/threat-model.md) §6.

> "What this doesn't do: full coercion resistance, protection against timing side
> channels, TLS between services, real KYC, or HSM-backed keys. Each is named,
> with the reason and the direction a production system would take."

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| `Cannot find package '@dvoting/…'` | The folder was moved. Run `npm install` to relink the workspaces. |
| `/vote` says the crypto bundle is missing | `npm run build:web` |
| Port already in use | A previous `npm run dev` is still running. Close it, or end the `node` processes. |
| Verifier says `NOT pinned` | You left out `--validators`. It still verifies, but warns that the anchor came from the chain itself. |
| Demo too slow on a weak laptop | `node services/ballot-box/src/scripts/full-election-demo.ts 6` runs with fewer voters. |

## Likely questions

| Question | Short answer |
|---|---|
| "Why a blockchain at all?" | It provides tamper evidence, not secrecy or correctness. Those come from the cryptography. MIT research (Park et al., 2021) shows treating a blockchain as the security mechanism is dangerous. |
| "Can the admin see my vote?" | No. The ballot box holds no key shares, and trustees only ever decrypt totals. |
| "What if the validators collude?" | With more than a third colluding, they can stall the chain. Even a full quorum cannot change the result undetectably: the recount catches it (`detects a forged result even when validators re-sign the forgery`). |
| "Can I prove how I voted?" | You can prove your ballot was counted, not what it said. That is deliberate, because proving content would enable vote-selling. |
| "Is it quantum-safe?" | No. RSA and discrete-log are both broken by a large quantum computer. The literature review covers post-quantum options. |
