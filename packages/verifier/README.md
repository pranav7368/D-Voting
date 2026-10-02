# @dvoting/verifier

Recount a D-Voting election on your own machine, trusting no D-Voting server.

```bash
npm run verify -- --url http://localhost:8082 --validators validators.json --save board.json
npm run verify -- --file board.json --validators validators.json
npm run verify -- --help
```

| Option | Purpose |
|---|---|
| `--url <base>` / `--file <path>` | Where the bulletin board comes from (exactly one) |
| `--validators <path>` | The trust anchor: `{"validators":[{"id","publicKey"}],"quorum":n}`, obtained out of band |
| `--roll <path>` | Published roll, one id per line. Checked against the sealed commitment |
| `--ballot <code>` | Prove a tracking code is on the chain (repeatable) |
| `--save <path>` | Keep the downloaded board for offline verification later |
| `--json` | Machine-readable report |

Exit codes: `0` verified, `1` a check failed, `2` the verifier could not run.

## What it checks

1. The chain is signed by the pinned validator set (or warns that none was pinned).
2. Every block's hash linkage, Merkle root and signature quorum, rebuilt locally.
3. The election definition is sealed once, in block 0.
4. Voting closed on the chain, and no ballot appears after the close.
5. Optionally: the roll commitment, and inclusion of specific ballots.
6. Every ballot's zero-knowledge proofs and the last-ballot-counts rule.
7. The published result uses the sealed trustee roster, and its encrypted totals,
   every decryption proof and the announced numbers all recompute.

Step 7 catches a false result **even when a quorum of validators signed it**.
Signatures prove who wrote the record, and only the recount proves the record is
right.

## Why `--validators` matters

Signatures prove that blocks were signed by *some* keys. Someone who controls a
whole chain file can sign it with keys of their own and seal those keys into a
fake block 0. Only a validator set obtained independently, for example published by
each validator operator, closes that gap. The report says which anchor was used
and prints the validator fingerprint so it can be compared by hand.
