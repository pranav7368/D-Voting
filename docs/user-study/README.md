# User study kit

Everything needed to run the D-Voting usability and manipulation-detection
study. Get ethics approval first.

| File | Use |
|---|---|
| [protocol.md](protocol.md) | Research questions, design, measures, analysis, ethics: the document for the ethics committee and the paper's method section |
| [facilitator-script.md](facilitator-script.md) | What to set up, what to say, how to score detection |
| [consent.md](consent.md) | Information sheet and consent form (fill in the bracketed fields) |
| [sus.md](sus.md) | System Usability Scale, scoring, open questions |
| [comprehension.md](comprehension.md) | Five questions on who learns what |
| [debrief.md](debrief.md) | Read to every participant at the end |
| [data-template.csv](data-template.csv) | One row per trial |

The study build is the normal system started with `STUDY_MODE=on`. A
facilitator's `?manipulate=1` link makes the voting page behave like a
compromised app; without study mode the parameter does nothing, and the server
refuses study mode in production.
