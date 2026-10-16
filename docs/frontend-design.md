# Frontend design

The voter page is designed around one idea: **the system's guarantees should be
visible while they are happening, in words a first-time voter understands.**
Everything below follows from that, and each decision cites the finding it
responds to.

## What the research says, and what we did about it

| Finding | Source | Design response |
|---|---|---|
| Many voters in early E2E-V systems failed to cast, and some *believed* they had cast when they had not. | Acemyan et al., EVT/WOTE 2014 | The task is the first thing on screen, at every width. Every step ends in an explicit state: "Your vote has been cast", with a timeline that only turns green when the public record confirms it. |
| Terms like "audit", "verifiability" and "ballot fingerprint" are not understood by voters. | Marky et al., CHI 2018 | Plain words throughout: the ballot is "locked" on the device, the credential is a "voting pass", and the Benaloh challenge is "Test this ballot instead", with one sentence on why it uses the ballot up. |
| A 43-character base64 fingerprint cannot be compared by a person. | Same; and the cast-as-intended literature generally | The review step shows a **12-digit check code** (`9896 4448 2543`), derived from the same SHA-256 commitment. Digits read the same in any script and can be compared with a second device. The full fingerprint is one click away. |
| Voters recognise candidates by symbol as much as by name; Indian ballots must offer NOTA. | ECI ballot-unit practice; Supreme Court of India, *PUCL v. Union of India* (2013) | The ballot is laid out like a ballot unit: serial number, name, party, symbol, one large target. NOTA is an optional, sealed last row. |
| Most voters in India read Hindi or a regional language first. | — | Every voter-facing string exists in English and Hindi and switches **in place**. A reload would destroy the in-memory credential. |
| Separation of knowledge is the system's central claim, but a footer paragraph does not convey it. | — | A **"Who knows what, right now"** panel updates at each step, stating per party what it has learned and what it never sees. |
| Small type excludes older voters. | WCAG 2.2 (1.4.4, 1.4.12) | 16px base, nothing under 13px, 50px touch targets, visible focus, reduced-motion support, real form controls so screen readers work. |

## Sealed presentation

Party, symbol and NOTA are part of the election definition sealed into block 0
(`candidateDetails` in `ElectionRecord`). A voter who recognises a candidate by
symbol is voting for the symbol, so swapping two symbols after opening would
misdirect votes as surely as swapping two names. The same rules apply as for
names: editable only in setup, refused once sealed.

The symbols are a fixed, neutral set drawn by the browser from
`public/symbols.js` (lamp, tree, star, book, bicycle, sun, boat, key, kite,
umbrella, flower, clock). No uploaded images, so the record carries no markup;
none is a real party's registered symbol, and each may be used once.

## The four steps

1. **Identify.** Polling-card fields, cleared from the page as soon as they are used.
2. **Choose.** The ballot sheet. Nothing has been sent yet, and the page says so.
3. **Check, then cast.** The locked choice with its symbol, the check code,
   *Cast*, *Change*, and, set apart, *Test this ballot instead*.
4. **Receipt.** Tracking code, a three-stage timeline read from the public
   bulletin board (received → sealed by *k* of *n* authorities → counted), and
   copy, verify and print. The printed receipt shows only the code, election,
   time and where to check it, never the choice.

## Constraints kept

- Strict CSP: no inline scripts or styles; every icon uses SVG presentation
  attributes only.
- Nothing is written to `localStorage` or `sessionStorage`, including the
  language choice.
- `voter.js` owns the protocol and `vote-page.js` owns the screen, so the
  cryptographic flow can be reviewed without reading layout code.

## Second-device check

The review step shows a QR code next to the check code, **before** the Cast and
Test buttons, because the phone must hold the commitment before the voting
device learns which way the voter will go. The values ride in the URL fragment
(`/check#e=…&b=…&c=…`), which is never sent to a server.

The phone page (`/check`) shows the same 12-digit code for comparison, then
waits on the public bulletin board until the ballot is sealed:

- **Tested:** it re-runs the audit from the published randomness and shows
  "This tested ballot contained: [symbol] Rohit Nair", then asks "Is this
  exactly what you selected?" with a plain answer for yes and for no.
- **Cast:** "Recorded exactly as shown". The sealed ballot's ciphertexts match
  the commitment, under a quorum of signatures. It says the choice stays secret.
- **Still waiting after 90 seconds:** a warning, because a device that cast a
  different ballot leaves the scanned one unsealed forever.

The QR encoder is `qrcode-generator` (MIT), pinned and bundled at build time
into `public/qrcode.js` with a published SHA-256, drawn as SVG paths so it
renders under the strict CSP.

## Still to do

- Hindi for the verify, results and public-record pages.
- An accessibility audit with a screen reader and with real voters (planned user study).
