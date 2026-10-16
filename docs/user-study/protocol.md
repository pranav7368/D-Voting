# User study protocol

**Title.** Can voters catch a dishonest voting app? A within-subjects study of
same-device versus second-device ballot checking in D-Voting.

**Status.** Ready for institutional ethics review. Do not recruit participants
before approval.

## 1. Research questions

- **RQ1. Detection.** When the voting app secretly encrypts a different
  candidate, how often do participants catch it with the same-device test
  (condition A) versus the second-device phone check (condition B)?
- **RQ2. Usability.** Is the voting flow usable, measured by the System
  Usability Scale (SUS), and does adding the phone check lower it?
- **RQ3. Comprehension.** After voting, do participants understand who learns
  what (the separation of knowledge the "Who knows what" panel shows)?
- **RQ4. Effort.** How long does each condition take, and how many participants
  complete the phone check without help?

**Hypotheses.** H1: detection is higher in B than in A (the same-device test
cannot reveal a lying app by construction; the study measures whether people
notice anything at all). H2: SUS in B is not more than 10 points below A.

## 2. Design

Within-subjects, two conditions, order counterbalanced (half A→B, half B→A).

| | Condition A: same-device test | Condition B: second-device check |
|---|---|---|
| Voting device | Laptop or desktop browser | Same |
| Check | "Test this ballot instead" on the voting device | Scan the QR code with the participant's own phone, then test and cast |
| Manipulated trial | Yes, one per condition | Yes, one per condition |

In each condition the participant votes **twice**: one honest trial and one
manipulated trial, in random order. In a manipulated trial the facilitator
opens the voting page with `?manipulate=1`. The app then encrypts the next
candidate on the ballot, keeps showing the participant's choice, and its own
test reports success. That is the behaviour of a compromised app.

Participants are told the study is about "checking that a voting app records
your choice correctly" and are asked to use the checks offered. They are not
told that some trials are manipulated (see §6, deception and debrief).

## 3. Participants

- **N = 30** (minimum 24). Adults 18+, comfortable using a smartphone camera.
  Aim for a mix: students, staff, and members of the public; record age band,
  gender (optional), prior e-voting experience, and self-rated tech comfort.
- **Exclusions.** Anyone who has seen D-Voting's code or design documents.
- **Sample size rationale.** For paired proportions (McNemar), detecting a
  difference of 20% vs 70% detection at α = 0.05 with power 0.8 needs roughly
  15 discordant pairs; 30 participants gives margin. SUS non-inferiority at a
  10-point margin with SD ≈ 15 needs about 20 participants.

## 4. Procedure (about 30 minutes)

1. Welcome, information sheet, consent (`consent.md`). Demographics.
2. Two-minute introduction read from the script (`facilitator-script.md`).
3. Condition 1: two voting trials, then SUS for that condition.
4. Condition 2: two voting trials, then SUS for that condition.
5. Comprehension questions (`comprehension.md`).
6. Debrief (`debrief.md`): reveal the manipulation, explain why, answer
   questions, offer withdrawal of data.

Each trial gives the participant a card naming the candidate to vote for, so no
personal political preference is ever involved.

## 5. Measures

| Measure | How | Analysis |
|---|---|---|
| Detection (per manipulated trial) | Participant reports a mismatch, refuses to cast, or asks for help citing the wrong candidate, before casting | McNemar test, A vs B; detection rate with 95% Wilson CI |
| False alarms (honest trials) | Participant reports a mismatch that does not exist | Descriptive |
| SUS (per condition) | Standard 10-item SUS, 0–100 (`sus.md`) | Wilcoxon signed-rank; mean ± SD; non-inferiority at 10 points |
| Task time | Facilitator timer, page load to receipt | Paired t-test or Wilcoxon |
| Phone check completion | Completed without help / with help / not completed | Descriptive |
| Comprehension | 5 questions, scored 0–5 (`comprehension.md`) | Descriptive; correlation with detection |
| Open feedback | Two open questions | Thematic coding |

Record everything in `data-template.csv`, one row per trial.

## 6. Ethics

- **Approval.** SRMIST Institutional Ethics Committee (or equivalent) before
  any recruitment.
- **No real votes, no personal preference.** Candidates are fictional; the
  participant is told whom to vote for.
- **Deception.** Withholding that some trials are manipulated is necessary:
  telling participants in advance would measure vigilance, not real
  behaviour. It is minimal (no harm, no personal data), and every participant
  is fully debriefed and may withdraw their data afterwards.
- **Data.** No names in the data file; participant codes only. Consent forms
  are stored separately. The study build keeps no logs of choices.
- **Safety of the build.** Study mode is enabled with `STUDY_MODE=on`, refuses
  to run with `NODE_ENV=production`, and shows a purple "Research study"
  banner on every page.

## 7. Running the study build

```bash
STUDY_MODE=on npm run dev        # PowerShell: $env:STUDY_MODE="on"; npm run dev
```

Then compose and open the study election in `/admin` (candidates in
`facilitator-script.md`). Use these links:

| Trial | Link |
|---|---|
| Honest | `http://<host>:8082/vote` |
| Manipulated | `http://<host>:8082/vote?manipulate=1` |

The phone needs to reach the ballot box and the witnesses over **HTTPS** (see
the note in `DEMO.md`). For a lab session, run the laptop behind an HTTPS
tunnel and open the voting page through it, so the QR code points to the same
address.

## 8. Threats to validity

- Lab setting and assigned candidates reduce the stakes compared with a real
  election; detection may be higher than in the field.
- The manipulation is always "next candidate"; a real attacker could be subtler.
- A student-heavy sample may be more tech-comfortable than the electorate.
- Learning effects between conditions are controlled by counterbalancing, not
  eliminated.
