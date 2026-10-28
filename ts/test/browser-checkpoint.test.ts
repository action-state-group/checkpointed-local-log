// The browser entry's checkpoint verifier, run in Node: the conformance
// vectors and a differential check against the Node entry, under each Ed25519
// path the browser entry can take.
import { createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as browser from "../src/browser.js";
import { verifyEd25519 } from "../src/ed25519-browser.js";
import * as node from "../src/index.js";
import {
  ed25519Cases,
  expectedMetadata,
  mutations,
  smallOrderKeyStatement,
  type CheckpointVectors,
  type CoseVectors,
} from "./browser-checkpoint-cases.js";

const load = <T>(name: string): T =>
  JSON.parse(
    readFileSync(
      resolve(
        process.env.CLL_ROOT ?? "..",
        "checkpoint-conformance-vectors",
        name,
      ),
      "utf8",
    ),
  ) as T;
const vectors = expectedMetadata(
  load<CoseVectors>("cose-vectors.json"),
  load<CheckpointVectors>("vectors.json"),
);

const nodeEd25519 = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean => {
  try {
    return edVerify(
      null,
      message,
      createPublicKey({
        key: Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          publicKey,
        ]),
        format: "der",
        type: "spki",
      }),
      signature,
    );
  } catch {
    return false;
  }
};

const realSubtle = globalThis.crypto.subtle;
// The browser entry hashes with WebCrypto where the page has it and with the
// plain SHA-256 where it does not; Ed25519 is always the plain verifier.
const modes: Record<string, () => () => void> = {
  "WebCrypto SHA-256": () => () =>
    expect(globalThis.crypto.subtle).toBe(realSubtle),
  "no crypto.subtle": () => {
    vi.stubGlobal("crypto", {});
    return () => expect(globalThis.crypto.subtle).toBeUndefined();
  },
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("browser entry checkpoint verifier", () => {
  it("exports the Node entry's verify-only names", () => {
    expect(browser.CHECKPOINT_CONTENT_TYPE).toBe(node.CHECKPOINT_CONTENT_TYPE);
    expect(typeof browser.verifyCheckpoint).toBe("function");
    expect(typeof browser.checkpointMetadata).toBe("function");
    expect("signCheckpoint" in browser).toBe(false);
  });

  for (const [mode, setUp] of Object.entries(modes)) {
    describe(mode, () => {
      for (const vector of vectors) {
        it(`accepts ${vector.name} with the Node entry's metadata`, async () => {
          const expected = await node.checkpointMetadata(vector.cose);
          const check = setUp();
          const metadata = await browser.checkpointMetadata(vector.cose);
          expect(await browser.verifyCheckpoint(vector.cose)).toBe(true);
          check();
          expect(metadata).toEqual(expected);
          expect(metadata).toMatchObject(vector.metadata);
        });

        it(`refuses every one-bit change to ${vector.name}, as Node does`, async () => {
          const statements = mutations(vector.cose);
          const expected = await Promise.all(
            statements.map((cose) => node.verifyCheckpoint(cose)),
          );
          expect(expected.every((result) => !result)).toBe(true);
          setUp();
          const results = await Promise.all(
            statements.map((cose) => browser.checkpointMetadata(cose)),
          );
          expect(results.every((result) => result === undefined)).toBe(true);
        });
      }

      it("matches Node on a fresh statement with cadence", async () => {
        const tree = new node.MmrTree();
        for (let i = 0; i < 5; i += 1)
          await tree.append(Uint8Array.from({ length: 32 }, () => i));
        const signed = await node.signCheckpoint({
          logId: "browser-log",
          mmrSize: tree.size,
          peaks: tree.peakHashes(),
          previousSize: 0n,
          previousPeaks: [],
          timestamp: "2026-10-27T12:00:00.5Z",
          identity: node.createCheckpointIdentity(new Uint8Array(32).fill(9)),
          cadence: 3,
        });
        const expected = await node.checkpointMetadata(signed.cose);
        setUp();
        expect(await browser.checkpointMetadata(signed.cose)).toEqual(expected);
        expect(expected?.cadence).toBe(3);
      });

      it("refuses what is not a statement", async () => {
        setUp();
        for (const input of [
          new Uint8Array(),
          Uint8Array.of(0xd2),
          new Uint8Array(70_000).fill(0xd2),
        ]) {
          expect(await browser.verifyCheckpoint(input)).toBe(false);
          expect(await browser.checkpointMetadata(input)).toBeUndefined();
        }
      });
    });
  }
});

describe("browser Ed25519", () => {
  const cases = ed25519Cases();

  it("refuses everything but the honest signature, and never accepts what Node refuses", () => {
    for (const edge of cases) {
      const nodeResult = nodeEd25519(
        edge.publicKey,
        edge.message,
        edge.signature,
      );
      const browserResult = verifyEd25519(
        edge.publicKey,
        edge.message,
        edge.signature,
      );
      expect({ name: edge.name, browserResult }).toEqual({
        name: edge.name,
        browserResult: edge.valid,
      });
      expect({ name: edge.name, nodeResult }).toEqual({
        name: edge.name,
        nodeResult: edge.valid,
      });
    }
  });

  it("refuses a statement signed for a small-order key, as Node does", async () => {
    const forged = smallOrderKeyStatement();
    expect(await node.verifyCheckpoint(forged)).toBe(false);
    expect(await browser.verifyCheckpoint(forged)).toBe(false);
    expect(await browser.checkpointMetadata(forged)).toBeUndefined();
  });

  it("does not use noble's cofactored verify, which accepts a mixed-order R", () => {
    const mixed = cases.find((edge) => edge.name === "mixed-order R")!;
    expect(
      ed25519.verify(mixed.signature, mixed.message, mixed.publicKey, {
        zip215: false,
      }),
    ).toBe(true);
    expect(nodeEd25519(mixed.publicKey, mixed.message, mixed.signature)).toBe(
      false,
    );
  });

  it("refuses inputs of the wrong length", () => {
    const [honest] = cases;
    expect(
      verifyEd25519(
        honest!.publicKey.subarray(1),
        honest!.message,
        honest!.signature,
      ),
    ).toBe(false);
    expect(
      verifyEd25519(
        honest!.publicKey,
        honest!.message,
        honest!.signature.subarray(1),
      ),
    ).toBe(false);
  });
});
