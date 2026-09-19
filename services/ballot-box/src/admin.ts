/**
 * Election administration.
 *
 * ===========================================================================
 * WHAT AN ADMINISTRATOR CAN AND CANNOT DO.
 *
 * A real election commission has real powers: it decides who stands, who is on
 * the roll, and when the poll opens and closes. Pretending otherwise would make
 * this a toy. So those powers are here.
 *
 * What is NOT here is any power to affect, see, or reverse the result:
 *
 *   - An admin CANNOT decrypt anything. The ballot box holds no trustee key
 *     shares, so there is no code path from this file to a plaintext vote.
 *     Decryption requires k of n trustees, each on their own machine.
 *   - An admin CANNOT see a running total. Status reports how many ballots were
 *     ACCEPTED, never how they lean.
 *   - An admin CANNOT alter or remove a recorded ballot. The ledger is
 *     append-only and every block carries a validator quorum this service
 *     cannot forge -- it holds no validator keys either.
 *   - An admin CANNOT change the election once the poll has opened. Candidates,
 *     limits and schedule are sealed into the chain at that moment, and every
 *     editing route refuses from then on.
 *   - An admin CANNOT reopen a closed election. The close is an entry on the
 *     chain, so it survives a restart -- which is what makes this a guarantee
 *     rather than a promise.
 *
 * And every action taken here is written to the audit log.
 * ===========================================================================
 */

import { Hono, type Context } from "hono";
import { z } from "zod";
import { constantTimeEqual, utf8 } from "@dvoting/crypto";

import { BallotBox, BallotBoxError } from "./ballot-box.ts";
import type { DecryptionCeremony } from "./ceremony.ts";
import { ElectionRecordError } from "./election-record.ts";
import { readPublishedTally } from "./tally-publication.ts";

export interface AdminOptions {
  ballotBox: BallotBox;
  ceremony: DecryptionCeremony;
  /** Bearer token. Required — there is no unauthenticated admin mode. */
  adminToken: string;
}

const draftSchema = z
  .object({
    name: z.string().max(200).nullish(),
    candidates: z.array(z.string().min(1).max(120)).min(2).max(64).optional(),
    minSelections: z.number().int().min(0).max(64).optional(),
    maxSelections: z.number().int().min(1).max(64).optional(),
  })
  .strict();

const openSchema = z
  .object({
    confirmElectionId: z.string().min(1).max(128),
    rollCommitment: z.string().max(128).nullish(),
    opensAt: z.string().max(64).nullish(),
    closesAt: z.string().max(64).nullish(),
  })
  .strict();

export function registerAdminRoutes(app: Hono, options: AdminOptions): void {
  const { ballotBox, ceremony, adminToken } = options;

  if (!adminToken || adminToken.length < 32) {
    throw new Error("registerAdminRoutes: adminToken must be at least 32 characters");
  }

  const authorise = (header: string | undefined): boolean => {
    const supplied = (header ?? "").replace(/^Bearer\s+/i, "");
    // Constant-time: a short-circuiting compare leaks the token a byte at a
    // time to anyone able to measure response latency.
    return constantTimeEqual(utf8(supplied), utf8(adminToken));
  };

  app.use("/v1/admin/*", async (c, next) => {
    if (!authorise(c.req.header("Authorization"))) {
      return c.json({ error: "unauthorized" }, 401);
    }
    // Admin responses describe election state; never let a proxy cache them.
    c.header("Cache-Control", "no-store");
    await next();
    return undefined;
  });

  app.get("/v1/admin/status", async (c) => {
    const election = await ballotBox.describe();
    const published = await readPublishedTally(ballotBox.ledger, election.electionId);
    const chain = await ballotBox.ledger.verify();
    const ceremonyStatus = await ceremony.status();

    return c.json({
      electionId: election.electionId,
      name: election.name,
      phase: published ? "published" : ballotBox.phase,
      candidates: election.candidates,
      minSelections: election.minSelections,
      maxSelections: election.maxSelections,
      sealed: election.configSealed,
      rollCommitment: election.rollCommitment,
      opensAt: election.opensAt,
      closesAt: election.closesAt,
      closedAt: election.closedAt,
      // Counts only. How the ballots lean is not knowable here, and must not be.
      ballotsAccepted: await countEntries(ballotBox, "ballot"),
      ballotsSpoiled: await countEntries(ballotBox, "spoiled-ballot"),
      pendingUnsealed: ballotBox.pendingCount,
      blockHeight: election.blockHeight,
      chainValid: chain.valid,
      chainErrors: chain.errors.slice(0, 5),
      validators: election.validators.map((v) => v.id),
      quorum: election.quorum,
      // Present so the dashboard can say "awaiting trustees" rather than
      // offering a button that cannot exist.
      ceremony: {
        phase: ceremonyStatus.phase,
        threshold: ceremonyStatus.threshold,
        total: ceremonyStatus.total,
        submitted: ceremonyStatus.submitted,
        outstanding: ceremonyStatus.outstanding,
      },
      resultPublished: published !== null,
      nextStep: nextStep(published !== null ? "published" : ballotBox.phase, ceremonyStatus),
    });
  });

  /**
   * Amend the draft ballot.
   *
   * Available only before the poll opens. `updateDraft` enforces that; this
   * route simply reports the refusal.
   */
  app.post("/v1/admin/election/draft", async (c) => {
    const parsed = draftSchema.safeParse(await readJson(c.req.raw));
    if (!parsed.success) {
      return c.json(
        { error: "invalid_request", message: "Send candidates and/or selection limits." },
        400,
      );
    }

    try {
      const election = ballotBox.updateDraft({
        ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
        ...(parsed.data.candidates !== undefined ? { candidates: parsed.data.candidates } : {}),
        ...(parsed.data.minSelections !== undefined
          ? { minSelections: parsed.data.minSelections }
          : {}),
        ...(parsed.data.maxSelections !== undefined
          ? { maxSelections: parsed.data.maxSelections }
          : {}),
      });
      await ballotBox.recordAdminAction(
        "admin.draft_updated",
        `${election.candidates.length} candidates, ${election.minSelections}-${election.maxSelections} selections`,
      );
      return c.json({
        name: election.name,
        candidates: election.candidates,
        minSelections: election.minSelections,
        maxSelections: election.maxSelections,
        sealed: false,
      });
    } catch (error) {
      return adminError(c, error);
    }
  });

  /**
   * Seal the election and open the poll.
   *
   * Requires the election id typed back, like closing does. This is the point
   * at which the configuration stops being editable forever, so it should not
   * be reachable by a stray click or a replayed request.
   */
  app.post("/v1/admin/election/open", async (c) => {
    const parsed = openSchema.safeParse(await readJson(c.req.raw));
    if (!parsed.success) {
      return c.json({ error: "invalid_request", message: "Malformed open request." }, 400);
    }
    if (parsed.data.confirmElectionId !== ballotBox.election.electionId) {
      return c.json(
        {
          error: "confirmation_required",
          message: `Send {"confirmElectionId":"${ballotBox.election.electionId}"} to confirm. The configuration cannot be changed afterwards.`,
        },
        400,
      );
    }

    try {
      const record = await ballotBox.openPoll({
        rollCommitment: parsed.data.rollCommitment ?? null,
        opensAt: parsed.data.opensAt ?? null,
        closesAt: parsed.data.closesAt ?? null,
      });
      await ballotBox.recordAdminAction(
        "admin.election_opened",
        `${record.candidates.length} candidates sealed at height ${await ballotBox.ledger.height()}`,
      );
      return c.json({
        phase: ballotBox.phase,
        sealed: true,
        record,
        blockHeight: await ballotBox.ledger.height(),
      });
    } catch (error) {
      return adminError(c, error);
    }
  });

  app.post("/v1/admin/seal", async (c) => {
    const block = await ballotBox.sealBlock();
    await ballotBox.recordAdminAction(
      "admin.seal",
      block ? `height ${block.header.height}` : "nothing pending",
    );
    return c.json({
      sealed: block !== null,
      height: block?.header.height ?? null,
      blockHeight: await ballotBox.ledger.height(),
    });
  });

  app.post("/v1/admin/close", async (c) => {
    // Require the election id as an explicit confirmation. Closing is one-way
    // and ends the franchise for anyone who has not yet voted; it should not be
    // possible to do it with a stray click or a replayed request.
    const body = (await readJson(c.req.raw)) as { confirmElectionId?: string } | null;
    if (body?.confirmElectionId !== ballotBox.election.electionId) {
      return c.json(
        {
          error: "confirmation_required",
          message: `Send {"confirmElectionId":"${ballotBox.election.electionId}"} to confirm. Closing cannot be undone.`,
        },
        400,
      );
    }

    try {
      const record = await ballotBox.closePoll("administrator");
      await ballotBox.recordAdminAction(
        "admin.close",
        `closed at height ${record.finalHeight}`,
      );
      return c.json({
        phase: "closed",
        closedAt: record.closedAt,
        finalBlockHeight: await ballotBox.ledger.height(),
        nextStep: nextStep("closed", await ceremony.status()),
      });
    } catch (error) {
      return adminError(c, error);
    }
  });

  app.get("/v1/admin/audit", async (c) => {
    const limit = Math.min(Number(c.req.query("limit") ?? 50), 500);
    return c.json({ entries: await ballotBox.recentAudit(limit) });
  });
}

type AdminPhase = "setup" | "scheduled" | "voting" | "closed" | "published";

function nextStep(phase: AdminPhase, ceremony: { submitted: readonly number[]; threshold: number }): string {
  switch (phase) {
    case "setup":
      return "Set the candidates, freeze the electoral roll, then open the poll. Opening seals the configuration to the chain and cannot be undone.";
    case "scheduled":
      return "The election is sealed and will start accepting ballots at the scheduled opening time.";
    case "voting":
      return "Close the poll when voting ends.";
    case "closed":
      return `Awaiting the trustee decryption ceremony: ${ceremony.submitted.length} of ${ceremony.threshold} shares submitted. This service cannot perform it -- it holds no key shares.`;
    case "published":
      return "Result is on the chain. Anyone can recount it from /v1/bulletin/result.";
  }
}

/** Map a domain error to a status code without leaking internals. */
function adminError(c: Context, error: unknown) {
  if (error instanceof BallotBoxError) {
    const conflict =
      error.code === "already_open" ||
      error.code === "already_closed" ||
      error.code === "election_sealed";
    return conflict
      ? c.json({ error: error.code, message: error.message }, 409)
      : c.json({ error: error.code, message: error.message }, 400);
  }
  if (error instanceof ElectionRecordError) {
    return c.json({ error: "invalid_configuration", message: error.message }, 400);
  }
  throw error;
}

async function countEntries(ballotBox: BallotBox, kind: string): Promise<number> {
  let count = 0;
  for (const block of await ballotBox.ledger.blocks()) {
    for (const entry of block.entries) {
      if (entry.kind === kind) count++;
    }
  }
  return count;
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
