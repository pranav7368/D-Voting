# API reference

Every service speaks JSON over HTTP. Administrative routes need the token printed at start-up; everything a voter or observer needs is public on purpose.

**Registration Authority**

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe |
| `GET /v1/issuer` | Public issuer key + `keyId`. Public and cacheable **on purpose** — every voter must confirm they got the same key as everyone else |
| `POST /v1/register` | Polling card in, short-lived registration token out |
| `POST /v1/credential/issue` | Token + blinded message in, blind signature out |
| `POST /v1/admin/roll` | Enrol voters; returns their enrolment codes **once** |
| `POST /v1/admin/roll/freeze` | Freeze the roll and return the commitment to seal |
| `GET /v1/admin/roll/export` | The roll identifiers, for publication |

**Ballot box**

| Endpoint | Purpose |
|---|---|
| `GET /v1/election` | Public descriptor: phase, candidates, keys, trustees, roll commitment |
| `POST /v1/ballots` | Cast. `POST /v1/ballots/audit` spoils and publishes an audited one |
| `GET /v1/bulletin/*` | The board: head, blocks, inclusion proofs, chain verification, result |
| `GET /v1/bulletin/audits/:id` | Inclusion receipt for a **tested** (spoiled) ballot, with its revealed randomness, for second-device checking |
| `GET /v1/bulletin/lookup/:id` | Whether a ballot id is sealed yet, and as cast or tested |
| `GET /v1/ceremony` | Public: the encrypted totals and which trustees have contributed |
| `POST /v1/ceremony/shares` | A trustee's partial decryptions. **No token** — the proof is the authentication |
| `POST /v1/admin/election/open` | Seal the election and open the poll. `…/close` ends it |

Witnesses serve `GET /v1/checkpoint` (their latest signed checkpoint and any alarm) and their own replica under `GET /v1/bulletin/head` and `/v1/bulletin/blocks/:height`. Trustees serve `GET /v1/status` and `POST /v1/participate`; validators serve `POST /v1/propose`, `/v1/attest` and `/v1/commit`. [RUNNING.md](../RUNNING.md#4-poke-the-api-directly) has ready-to-paste `curl` calls.
