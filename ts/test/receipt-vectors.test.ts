// checkpoint-conformance-vectors/receipt-vectors.json, shared by every
// implementation: the witness receipts agent-action-capsule's
// VerifyCOSEReceipt accepts and refuses.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { ReceiptVerifier } from "../src/receipt.js";
import { fromHex } from "./browser-checkpoint-cases.js";

interface ReceiptVectors {
  readonly checkpoint_cose_b64: string;
  readonly entry_hash_hex: string;
  readonly authority_public_key_hex: string;
  readonly cases: readonly {
    readonly name: string;
    readonly accept: boolean;
    readonly tree_size: number;
    readonly leaf_index: number;
    readonly receipt_b64: string;
  }[];
}

const vectors = JSON.parse(
  readFileSync(
    resolve(
      process.env.CLL_ROOT ?? "..",
      "checkpoint-conformance-vectors",
      "receipt-vectors.json",
    ),
    "utf8",
  ),
) as ReceiptVectors;

describe("receipt vectors", () => {
  const verifier = new ReceiptVerifier(
    fromHex(vectors.authority_public_key_hex),
  );
  const checkpoint = Buffer.from(vectors.checkpoint_cose_b64, "base64");
  const receipt = (
    edge: ReceiptVectors["cases"][number],
    treeSize: number,
  ) => ({
    bytes: Buffer.from(edge.receipt_b64, "base64"),
    entryHash: vectors.entry_hash_hex,
    entryHashScheme: "legacy" as const,
    treeSize,
    leafIndex: edge.leaf_index,
  });

  it("decides every case", async () => {
    const results = [];
    for (const edge of vectors.cases)
      results.push({
        name: edge.name,
        accept: await verifier.verify(
          checkpoint,
          receipt(edge, edge.tree_size),
        ),
      });
    expect(results).toEqual(
      vectors.cases.map(({ name, accept }) => ({ name, accept })),
    );
  });

  it("refuses an accepted receipt stored at another position", async () => {
    for (const edge of vectors.cases.filter(({ accept }) => accept))
      expect(
        await verifier.verify(checkpoint, receipt(edge, edge.tree_size + 1)),
      ).toBe(false);
  });
});
