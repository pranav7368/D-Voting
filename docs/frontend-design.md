# Frontend design direction

This interface is for voters first, with companion views for observers, election administrators, and trustees. The visual system uses a restrained navy, cobalt, and mint palette, generous space, and one primary action per step. The ballot and verification views share navigation, typography, cards, and status language.

## Research translated into the interface

- [GOV.UK question page pattern](https://design-system.service.gov.uk/patterns/question-pages/): each voting step has a clear heading and continue action. The four-step indicator shows progress without becoming navigation.
- [GOV.UK validation pattern](https://design-system.service.gov.uk/patterns/validation/) and [error message guidance](https://design-system.service.gov.uk/components/error-message/): prompts name the field or choice that needs attention and keep entered values available for correction.
- [Helios audited ballots](https://vote.heliosvoting.org/helios/elections/f72c510a-c3ca-11f0-80dd-12f2d6ac8e9e/audited-ballots/): the review step explains clearly that auditing reveals and spoils that prepared ballot, so the voter must prepare another to cast.
- [GOV.UK accessibility strategy](https://design-system.service.gov.uk/accessibility/accessibility-strategy/): progress, errors, and completion use text as well as color. Focus moves to the next step heading, keyboard outlines remain visible, and reduced motion is respected.

## Product decisions

The illustration is decorative and has an empty alternative text. Live election status, available candidates, quorum, and result states come from the application. The hero never claims that an election is open when it is not. The admin and trustee views retain their own credentials and operations; the design only changes their presentation.

The voter journey now supports a ballot that allows multiple selections, including optional selections when the minimum is zero. Review includes a change-selection action that discards only the locally prepared ballot. Credentials and vote choices remain in tab memory under the existing protocol.

## Generated image

The original transparent PNG is `services/ballot-box/public/ballot-hero.png`. It was created with the built-in image generation tool using this prompt:

> A premium 3D editorial illustration for a modern, trustworthy end-to-end verifiable online voting application: a translucent frosted-glass ballot card with three choice lines and one cobalt selection circle, slipping into a translucent ballot box. A luminous verification check and delicate linked data nodes. Calm civic technology aesthetic, soft studio lighting, midnight navy and cobalt with mint and ivory accents. Isolated composition with whitespace. No people, flags, political insignia, logos, letters, readable text, or watermark. Transparent background.

The image is a decorative cue; ballot options, status, and proof data remain live HTML text.
