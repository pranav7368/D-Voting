/**
 * Electoral roll administration.
 *
 * ===========================================================================
 * THIS IS THE MOST DANGEROUS SURFACE IN THE SYSTEM. HERE IS WHY, AND WHAT
 * CONSTRAINS IT.
 *
 * Everything else in D-Voting is designed so that cheating is detectable.
 * Adding voters is the exception: a fabricated roll entry produces a
 * cryptographically perfect ballot, and no proof anywhere in the protocol
 * distinguishes it from a real one. That is not a flaw in the cryptography --
 * it is the boundary of what cryptography can do. Eligibility is a claim about
 * the world, and the world is not verifiable by hashing it.
 *
 * So the constraints here are procedural, and they mirror how a real commission
 * is held to account:
 *
 *   - ENROLMENT CODES ARE SHOWN ONCE. They are generated here, returned in the
 *     response, and stored only as an HMAC. Not even this service can print a
 *     voter's polling card twice.
 *   - THE ROLL CAN BE FROZEN, AND FREEZING IS ONE-WAY. After that, additions
 *     are refused outright.
 *   - FREEZING PRODUCES A COMMITMENT that is sealed onto the chain when the
 *     poll opens. Publish the roll and anyone can check the two match.
 *   - REVOCATION IS RECORDED, NOT ERASED. A revoked entry stays in the roll and
 *     therefore in the commitment; it simply stops authenticating.
 *
 * What an administrator still cannot do, even here: learn who has voted, learn
 * whether a particular voter voted, or link a roll entry to a ballot. This
 * service never sees a ballot at all.
 * ===========================================================================
 */

import { Hono } from "hono";
import { z } from "zod";
import { constantTimeEqual, utf8 } from "@dvoting/crypto";

import {
  RollFrozenError,
  type ElectoralRollStore,
} from "./eligibility/electoral-roll.ts";
import { generateEnrolmentCode, hashEnrolmentCode } from "./eligibility/enrolment-code.ts";
import { rollCommitment } from "./eligibility/roll-commitment.ts";
import type { VoterRepository } from "./repo/types.ts";

export interface RollAdminOptions {
  rollStore: ElectoralRollStore;
  repository: VoterRepository;
  electionId: string;
  /** Pepper for enrolment-code HMACs. Shared with the eligibility verifier. */
  pepper: string;
  adminToken: string;
}

const addSchema = z
  .object({
    /** Generate this many sequential entries. Mutually exclusive with rollIds. */
    count: z.number().int().min(1).max(10_000).optional(),
    /** Explicit roll identifiers, e.g. imported from a statutory register. */
    rollIds: z.array(z.string().min(1).max(128)).min(1).max(10_000).optional(),
    /** Prefix for generated identifiers. */
    prefix: z.string().min(1).max(32).default("R-"),
  })
  .strict()
  .refine((v) => (v.count === undefined) !== (v.rollIds === undefined), {
    message: "supply exactly one of count or rollIds",
  });

const revokeSchema = z.object({ rollId: z.string().min(1).max(128) }).strict();

export function registerRollAdminRoutes(app: Hono, options: RollAdminOptions): void {
  const { rollStore, repository, electionId, pepper, adminToken } = options;

  if (!adminToken || adminToken.length < 32) {
    throw new Error("registerRollAdminRoutes: adminToken must be at least 32 characters");
  }

  app.use("/v1/admin/*", async (c, next) => {
    const supplied = (c.req.header("Authorization") ?? "").replace(/^Bearer\s+/i, "");
    if (!constantTimeEqual(utf8(supplied), utf8(adminToken))) {
      return c.json({ error: "unauthorized" }, 401);
    }
    c.header("Cache-Control", "no-store");
    await next();
    return undefined;
  });

  /** Roll size, freeze state, and the commitment as it stands. */
  app.get("/v1/admin/roll", async (c) => {
    const rollIds = await rollStore.listRollIds(electionId);
    return c.json({
      electionId,
      entries: rollIds.length,
      frozen: await rollStore.isFrozen(electionId),
      commitment: await rollCommitment(electionId, rollIds),
      // Identifiers are not secret -- a roll is normally a published document --
      // but the response is capped so this does not become a bulk export route.
      sample: rollIds.slice(0, 25),
    });
  });

  /**
   * Add voters, returning their enrolment codes exactly once.
   *
   * The codes exist in this response and nowhere else. They are printed onto
   * polling cards and delivered to voters; the service keeps only an HMAC, so a
   * database compromise does not yield a single usable code, and a lost card
   * means a new entry rather than a reprint.
   */
  app.post("/v1/admin/roll", async (c) => {
    const parsed = addSchema.safeParse(await readJson(c.req.raw));
    if (!parsed.success) {
      return c.json(
        { error: "invalid_request", message: parsed.error.issues[0]?.message ?? "Malformed request." },
        400,
      );
    }

    if (await rollStore.isFrozen(electionId)) {
      return c.json(
        {
          error: "roll_frozen",
          message: "The roll is frozen. It was committed to the chain and cannot be added to.",
        },
        409,
      );
    }

    let rollIds: string[];
    if (parsed.data.rollIds) {
      rollIds = parsed.data.rollIds.map((id) => id.trim()).filter(Boolean);
      if (new Set(rollIds).size !== rollIds.length) {
        return c.json({ error: "duplicate_roll_ids", message: "The list repeats a roll id." }, 400);
      }
    } else {
      // Continue the sequence rather than restarting it, so a second batch does
      // not collide with the first.
      const existing = await rollStore.listRollIds(electionId);
      let next = 100_001;
      for (const id of existing) {
        const numeric = Number(id.replace(/^\D+/, ""));
        if (Number.isFinite(numeric) && numeric >= next) next = numeric + 1;
      }
      rollIds = Array.from({ length: parsed.data.count! }, (_, i) => `${parsed.data.prefix}${next + i}`);
    }

    const cards: { rollId: string; enrolmentCode: string }[] = [];
    for (const rollId of rollIds) {
      const enrolmentCode = generateEnrolmentCode();
      try {
        await rollStore.addEntry({
          rollId,
          electionId,
          enrolmentCodeHash: await hashEnrolmentCode(pepper, rollId, enrolmentCode),
        });
      } catch (error) {
        if (error instanceof RollFrozenError) {
          return c.json({ error: "roll_frozen", message: error.message }, 409);
        }
        // Partial success is reported honestly: the entries before this one are
        // already in the roll, and their cards must still be delivered.
        return c.json(
          {
            error: "duplicate_roll_id",
            message: `"${rollId}" is already on the roll. ${cards.length} entries were added before this failure.`,
            cards,
          },
          409,
        );
      }
      cards.push({ rollId, enrolmentCode });
    }

    await repository.recordAudit({
      electionId,
      action: "roll.entries_added",
      detail: `${cards.length} entries`,
    });

    return c.json({ added: cards.length, cards }, 201);
  });

  /**
   * Revoke one entry.
   *
   * The entry stays on the roll and therefore inside the commitment; only its
   * ability to authenticate is removed. Deleting it would silently change the
   * digest the election was opened with.
   */
  app.post("/v1/admin/roll/revoke", async (c) => {
    const parsed = revokeSchema.safeParse(await readJson(c.req.raw));
    if (!parsed.success) {
      return c.json({ error: "invalid_request", message: "Send {rollId}." }, 400);
    }

    const revoked = await rollStore.revokeEntry(electionId, parsed.data.rollId);
    await repository.recordAudit({
      electionId,
      action: revoked ? "roll.revoked" : "roll.revoke_noop",
      detail: parsed.data.rollId,
    });

    if (!revoked) {
      return c.json(
        { error: "not_found", message: "No active entry with that roll id." },
        404,
      );
    }
    return c.json({ revoked: true, rollId: parsed.data.rollId });
  });

  /**
   * Freeze the roll and return the commitment to seal onto the chain.
   *
   * Idempotent: calling it again returns the same digest, because the roll can
   * no longer change. That matters -- an operator who loses the response must be
   * able to recover the value without a second, different freeze.
   */
  app.post("/v1/admin/roll/freeze", async (c) => {
    await rollStore.freeze(electionId);
    const rollIds = await rollStore.listRollIds(electionId);
    const commitment = await rollCommitment(electionId, rollIds);

    await repository.recordAudit({
      electionId,
      action: "roll.frozen",
      detail: `${rollIds.length} entries, commitment ${commitment.slice(0, 12)}`,
    });

    return c.json({
      frozen: true,
      entries: rollIds.length,
      commitment,
      message: "Seal this commitment into the election when you open the poll.",
    });
  });

  /**
   * The full list of roll identifiers, for publication.
   *
   * Separate from the summary route on purpose: publishing the roll is a
   * deliberate act, and it is what makes the commitment checkable by anyone.
   * Enrolment-code hashes are never included.
   */
  app.get("/v1/admin/roll/export", async (c) => {
    const rollIds = await rollStore.listRollIds(electionId);
    return c.json({
      electionId,
      entries: rollIds.length,
      commitment: await rollCommitment(electionId, rollIds),
      rollIds,
      note: "Publish this list. Anyone can recompute the commitment from it and compare it with the chain.",
    });
  });
}

async function readJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}
