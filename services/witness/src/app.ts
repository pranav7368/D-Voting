/**
 * Witness HTTP surface. Read-only, public, and deliberately boring.
 *
 *   GET /v1/checkpoint         the latest signed checkpoint, plus any alarm
 *   GET /v1/status             what this witness holds and whether it is alarmed
 *   GET /v1/bulletin/head      this witness's own copy of the board, in the
 *   GET /v1/bulletin/blocks/:h same shape the ballot box serves, so an auditor
 *                              can download the record from a witness instead
 *
 * Open to every origin: voters' devices call this from the ballot box's pages,
 * and an observer's checkpoint is worth more the more people can read it.
 * Nothing here accepts input that changes state.
 */

import { Hono } from "hono";
import { toBase64Url } from "@dvoting/crypto";
import { blockHash, blockToWire, checkpointToWire, type BlockStore } from "@dvoting/ledger";

import type { Witness } from "./witness.ts";

export function createApp(options: { witness: Witness; store: BlockStore }): Hono {
  const { witness, store } = options;
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("Access-Control-Allow-Origin", "*");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  });

  app.get("/health", (c) => c.json({ status: "ok", service: "witness", id: witness.id }));

  app.get("/v1/status", async (c) => {
    c.header("Cache-Control", "no-store");
    return c.json(await witness.status());
  });

  app.get("/v1/checkpoint", async (c) => {
    c.header("Cache-Control", "no-store");
    const status = await witness.status();
    const latest = witness.latest;
    if (!latest) {
      return c.json({ error: "nothing_witnessed", message: "This witness has not seen the election open yet.", alarm: status.alarm }, 503);
    }
    // The last good checkpoint stays available after an alarm: ballots sealed
    // before the fork are still vouched for. The alarm travels with it, so no
    // device can read the checkpoint without also seeing the warning.
    return c.json({ checkpoint: checkpointToWire(latest), alarm: status.alarm });
  });

  app.get("/v1/bulletin/head", async (c) => {
    const head = await store.head();
    return c.json({
      height: await store.height(),
      head: head ? { ...blockToWire(head).header, hash: toBase64Url(await blockHash(head.header)) } : null,
    });
  });

  app.get("/v1/bulletin/blocks/:height", async (c) => {
    const height = Number(c.req.param("height"));
    if (!Number.isInteger(height) || height < 0) return c.json({ error: "invalid_height" }, 400);
    const block = await store.getByHeight(height);
    if (!block) return c.json({ error: "not_found" }, 404);
    c.header("Cache-Control", "public, max-age=31536000, immutable");
    return c.json({ ...blockToWire(block), hash: toBase64Url(await blockHash(block.header)) });
  });

  app.notFound((c) => c.json({ error: "not_found" }, 404));
  return app;
}
