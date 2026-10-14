import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decode } from "cborg";
import { describe, expect, it } from "vitest";
import * as node from "../src/mmr-node.js";
import * as browser from "../src/browser.js";
import { createCheckpointIdentity, signCheckpoint } from "../src/index.js";

// Byte-for-byte copy of checkpointed-local-log/cll-02-vectors/vectors.json;
// cll-02-vectors/generate.py --check keeps it identical.
type ProofJson = {
  tree_size_1: number;
  tree_size_2: number;
  consistency_paths: string[][];
  right_peaks: string[];
};
const v = JSON.parse(
  readFileSync(resolve("test/testdata/cll-02-vectors.json"), "utf8"),
) as {
  entries: string[];
  nodes: string[];
  kid: string;
  conventions: { log_identity: { sub: string } };
  sizes: {
    leaf_count: number;
    log_size: number;
    peaks: string[];
    commitment: string;
  }[];
  checkpoints: {
    id: string;
    claims: {
      log_size: number;
      prev_size: number;
      issued_at: string;
      cadence: number;
    };
    claims_hex: string;
    consistency_proof: ProofJson | null;
  }[];
};
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

type Mmr = typeof node;
const build = async (m: Mmr) => {
  const tree = new m.MmrTree();
  const sizes = [0n];
  for (const entry of v.entries)
    sizes.push(await tree.appendHexIdentity(entry));
  return { tree, sizes };
};

describe.each([
  ["node", node],
  ["browser", browser as unknown as Mmr],
])("cll -02 log layer (%s)", (_, m) => {
  it("node values, log_size as the node count, and every accumulator", async () => {
    const { tree, sizes } = await build(m);
    expect(tree.nodes().map(hex)).toEqual(v.nodes);
    for (const row of v.sizes) {
      expect(sizes[row.leaf_count]).toBe(BigInt(row.log_size));
      const peaks = await tree.peakHashesAt(BigInt(row.log_size));
      expect(peaks.map(hex)).toEqual(row.peaks);
      expect(hex(Buffer.concat(peaks))).toBe(row.commitment);
      if (row.log_size > 0)
        expect(m.leafCount(BigInt(row.log_size))).toBe(BigInt(row.leaf_count));
    }
  });

  it("the consistency proof carries the profile proof losslessly", async () => {
    const { tree } = await build(m);
    const proofs = v.checkpoints.flatMap((cp) =>
      cp.consistency_proof ? [cp.consistency_proof] : [],
    );
    expect(proofs).toHaveLength(2);
    for (const want of proofs) {
      const partial = new m.MmrTree(tree.nodes().slice(0, want.tree_size_2));
      const p = await m.consistencyProof(
        partial,
        BigInt(want.tree_size_1),
        BigInt(want.tree_size_2),
      );
      expect(p.witness).toEqual(want.consistency_paths);
      expect(
        p.new_peaks.slice(p.new_peaks.length - want.right_peaks.length),
      ).toEqual(want.right_peaks);
    }
  });
});

// The -02 wire form is ahead of this package, which still emits the -01 form.
// These pin the gap: each fails the day the package emits -02, and must then
// become a plain equality test.
describe("cll -02 wire layer (pending the CLL 0.2 wire release)", () => {
  it("claims bytes still differ from -02", async () => {
    const { tree } = await build(node);
    const identity = createCheckpointIdentity(new Uint8Array(32).fill(7));
    expect(hex(identity.publicKey)).toBe(v.kid);
    let compared = 0;
    for (const cp of v.checkpoints) {
      const c = cp.claims;
      // signCheckpoint refuses log_size == prev_size (cp3); -02 permits it.
      if (c.prev_size === c.log_size) continue;
      const proof =
        c.prev_size > 0
          ? await new node.MmrTree(
              tree.nodes().slice(0, c.log_size),
            ).consistencyProof(BigInt(c.prev_size))
          : undefined;
      const signed = await signCheckpoint({
        logId: v.conventions.log_identity.sub,
        mmrSize: BigInt(c.log_size),
        peaks: await tree.peakHashesAt(BigInt(c.log_size)),
        previousSize: BigInt(c.prev_size),
        previousPeaks: await tree.peakHashesAt(BigInt(c.prev_size)),
        timestamp: c.issued_at,
        identity,
        cadence: c.cadence,
        ...(proof
          ? {
              consistencyProof: {
                sizeA: proof.oldSize,
                sizeB: proof.newSize,
                oldPeaks: proof.oldPeaks,
                witness: proof.witness,
                newPeaks: proof.newPeaks,
              },
            }
          : {}),
      });
      const [protectedBytes, , payload] = decode(signed.cose.subarray(1)) as [
        Uint8Array,
        unknown,
        Uint8Array,
      ];
      expect(hex(payload)).not.toBe(cp.claims_hex);
      const header = decode(protectedBytes, { useMaps: true }) as Map<
        number,
        unknown
      >;
      const cwt = header.get(15) as Map<number, unknown>;
      expect(cwt.get(2)).not.toBe(v.conventions.log_identity.sub);
      compared += 1;
    }
    expect(compared).toBe(3);
  });
});
