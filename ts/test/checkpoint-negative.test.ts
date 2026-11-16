import { sign as edSign } from "node:crypto";

import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { describe, expect, it } from "vitest";
import {
  createCheckpointIdentity,
  MmrTree,
  checkpointRejectionField,
  signCheckpoint,
  verifyCheckpoint,
  type SignedCheckpoint,
} from "../src/index.js";

const identity = createCheckpointIdentity(new Uint8Array(32));
const canonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);
const firstTree = async (): Promise<MmrTree> => {
  const tree = new MmrTree();
  await tree.append(Buffer.from("11".repeat(32), "hex"));
  return tree;
};
const firstCheckpoint = async (timestamp = "2026-09-01T12:34:56Z") => {
  const tree = await firstTree();
  return signCheckpoint({
    logId: "negative-test",
    mmrSize: tree.size,
    peaks: tree.peakHashes(),
    previousSize: 0n,
    previousPeaks: [],
    timestamp,
    identity,
  });
};

function authenticatedMutation(
  checkpoint: SignedCheckpoint,
  mutate: (headers: Map<number, unknown>, claims: Map<string, unknown>) => void,
): Uint8Array {
  const items = decode(checkpoint.cose.subarray(1), {
    allowIndefinite: false,
    useMaps: true,
  }) as unknown[];
  const headers = decode(items[0] as Uint8Array, {
    allowIndefinite: false,
    useMaps: true,
  }) as Map<number, unknown>;
  const claims = decode(items[2] as Uint8Array, {
    allowIndefinite: false,
    useMaps: true,
  }) as Map<string, unknown>;
  mutate(headers, claims);
  const protectedBytes = canonical(headers);
  const payload = canonical(claims);
  const signature = edSign(
    null,
    canonical(["Signature1", protectedBytes, new Uint8Array(), payload]),
    identity.privateKey,
  );
  return Buffer.concat([
    Uint8Array.of(0xd2),
    canonical([protectedBytes, new Map(), payload, signature]),
  ]);
}

describe("checkpoint verifier negative boundaries", () => {
  it("rejects an indefinite-length non-canonical COSE array", async () => {
    const checkpoint = await firstCheckpoint();
    const items = decode(checkpoint.cose.subarray(1), {
      allowIndefinite: false,
      useMaps: true,
    }) as unknown[];
    const indefinite = Buffer.concat([
      Uint8Array.of(0xd2, 0x9f),
      ...items.map((item) => canonical(item)),
      Uint8Array.of(0xff),
    ]);
    expect(await verifyCheckpoint(indefinite)).toBe(false);
  });

  it("rejects authenticated protected-header and CWT errors", async () => {
    const checkpoint = await firstCheckpoint();
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (headers) => {
          headers.set(3, "application/not-a-checkpoint");
        }),
      ),
    ).toBe(false);
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (headers) => {
          (headers.get(15) as Map<number, unknown>).set(2, "wrong#1");
        }),
      ),
    ).toBe(false);
  });

  it("rejects an authenticated commitment inconsistent with log size", async () => {
    const checkpoint = await firstCheckpoint();
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          claims.set("commitment", canonical([]));
        }),
      ),
    ).toBe(false);
  });

  it("rejects an authenticated invalid consistency proof", async () => {
    const tree = await firstTree();
    const previousPeaks = tree.peakHashes();
    await tree.append(Buffer.from("22".repeat(32), "hex"));
    const proof = await tree.consistencyProof(1n);
    const checkpoint = await signCheckpoint({
      logId: "negative-test",
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 1n,
      previousPeaks,
      timestamp: "2026-09-01T12:34:56Z",
      identity,
      consistencyProof: {
        sizeA: proof.oldSize,
        sizeB: proof.newSize,
        oldPeaks: proof.oldPeaks,
        witness: proof.witness,
        newPeaks: proof.newPeaks,
      },
    });
    expect(await verifyCheckpoint(checkpoint.cose)).toBe(true);
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          const consistency = claims.get("consistency_proof") as Map<
            string,
            unknown
          >;
          consistency.set("size_a", 2);
        }),
      ),
    ).toBe(false);
  });

  it("preserves and verifies microsecond timestamps", async () => {
    const checkpoint = await firstCheckpoint("2026-09-01T12:34:56.123456Z");
    expect(checkpoint.timestamp).toBe("2026-09-01T12:34:56.123456Z");
    expect(await verifyCheckpoint(checkpoint.cose)).toBe(true);
  });

  it("renders checkpoint fractions with Go RFC3339Nano trimming", async () => {
    const checkpoint = await firstCheckpoint("2026-09-01T12:34:56.836000Z");
    expect(checkpoint.timestamp).toBe("2026-09-01T12:34:56.836Z");
    expect(Buffer.from(checkpoint.json).toString()).toContain(
      '"timestamp":"2026-09-01T12:34:56.836Z"',
    );
    expect(await verifyCheckpoint(checkpoint.cose)).toBe(true);
  });

  it.each([
    "2026-10-02T02:40:00.000Z",
    "2026-10-02T02:40:00.5Z",
    "2026-10-02T02:40:00.1234567891Z",
    "0000-02-29T00:00:00Z",
    "2026-10-02T02:40:00+00:00",
  ])("accepts an authenticated issued_at spelled %s", async (issuedAt) => {
    const checkpoint = await firstCheckpoint();
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          claims.set("issued_at", issuedAt);
        }),
      ),
    ).toBe(true);
  });

  it.each([
    "yesterday",
    "2026-10-02 02:40:00Z",
    "2026-02-30T00:00:00Z",
    "2026-10-02T02:40:00,5Z",
    "2026-10-02T02:40:00+24:00",
    "2026-10-02T02:40:00.Z",
    "2026-10-02T24:00:00Z",
    "",
  ])("rejects an authenticated issued_at of %j", async (issuedAt) => {
    const checkpoint = await firstCheckpoint();
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          claims.set("issued_at", issuedAt);
        }),
      ),
    ).toBe(false);
  });

  it("rejects an authenticated issued_at that is not text", async () => {
    const checkpoint = await firstCheckpoint();
    expect(
      await verifyCheckpoint(
        authenticatedMutation(checkpoint, (_headers, claims) => {
          claims.set("issued_at", 1760000000);
        }),
      ),
    ).toBe(false);
  });

  describe("checkpointRejectionField", () => {
    const withIssuedAt = async (value: unknown) =>
      authenticatedMutation(await firstCheckpoint(), (_headers, claims) => {
        claims.set("issued_at", value);
      });

    it.each(["yesterday", "2026-02-30T00:00:00Z", "", 1760000000])(
      "names issued_at when it is %j",
      async (issuedAt) => {
        const cose = await withIssuedAt(issuedAt);
        expect(await verifyCheckpoint(cose)).toBe(false);
        expect(checkpointRejectionField(cose)).toBe("issued_at");
      },
    );

    it("names nothing for a valid checkpoint or a legacy .000Z spelling", async () => {
      expect(
        checkpointRejectionField((await firstCheckpoint()).cose),
      ).toBeUndefined();
      expect(
        checkpointRejectionField(
          await withIssuedAt("2026-10-02T02:40:00.000Z"),
        ),
      ).toBeUndefined();
    });

    it("names nothing for a tampered signature with a well-formed issued_at", async () => {
      const cose = Uint8Array.from((await firstCheckpoint()).cose);
      cose[cose.length - 1] = (cose[cose.length - 1] ?? 0) ^ 0xff;
      expect(await verifyCheckpoint(cose)).toBe(false);
      expect(checkpointRejectionField(cose)).toBeUndefined();
    });

    it("names nothing for bytes that are not a checkpoint", () => {
      expect(checkpointRejectionField(new Uint8Array())).toBeUndefined();
      expect(
        checkpointRejectionField(Uint8Array.of(0xd2, 0x80)),
      ).toBeUndefined();
    });
  });
});
