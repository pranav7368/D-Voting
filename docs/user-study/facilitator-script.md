# Facilitator script

Read the boxed text aloud. Keep everything else to yourself.

## Before the session

1. Start the study build (`STUDY_MODE=on npm run dev`) behind the HTTPS tunnel.
2. In `/admin`, compose the study election:
   ```
   Asha Verma | Progressive Students Front | lamp
   Rohit Nair | Campus Unity Alliance | tree
   Meera Iyer | Independent | book
   ```
   Tick "Add NOTA". Choose exactly 1. Open the poll.
3. Take four polling cards from `.local/cards.csv` for this participant.
4. Check the participant's order sheet: condition order (AB or BA) and, within
   each condition, which trial is manipulated (1st or 2nd).
5. Prepare four candidate cards ("Please vote for: Rohit Nair", etc.).

## Introduction

> Thank you for helping. Today you will try an online voting app and check that
> it records your vote correctly. You will vote four times, always for the
> candidate on the card I give you, so your own opinions are never involved.
> The app offers ways to check your ballot. Please use them as you would if this
> were a real election. If anything looks wrong, say so. There are no wrong
> answers; we are testing the app, not you.

## Condition A: same-device test

> For these two votes, before casting, use the "Test this ballot instead" button
> on the screen at least once, then vote.

For each trial: hand over a polling card and a candidate card, open the honest
or manipulated link, start the timer. Stop at the receipt or when the
participant reports a problem. Note anything they say about a mismatch.

## Condition B: second-device check

> For these two votes, use your phone. Before casting, scan the code on the
> screen with your phone camera, then use "Test this ballot instead" at least
> once and watch your phone. Then vote, and check your phone again.

Same procedure. Note whether the phone check was completed with or without help.

## After each condition

Hand over the SUS sheet for that condition.

## Scoring detection

A manipulated trial counts as **detected** if, before casting, the participant
says the candidate shown anywhere (screen or phone) is not the one they chose,
refuses to cast, or asks for help naming the wrong candidate. Record their
words.

## Do not

- hint that something might be wrong;
- explain what the phone shows before they look;
- help with the phone unless they ask (then record "with help").
