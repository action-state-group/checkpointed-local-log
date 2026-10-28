import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { ReceiptVerifier, type WitnessReceipt } from "../src/index.js";

const fixture = resolve("test/fixtures/capsule-anchor-leg1");
const checkpoint = readFileSync(resolve(fixture, "checkpoint.cose"));
const receiptBytes = readFileSync(resolve(fixture, "receipt.cose"));
const authorityKey = Buffer.from(
  "39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5",
  "hex",
);
const receipt: Required<WitnessReceipt> = {
  bytes: receiptBytes,
  entryHash: "b16766df5e64792852c1da1210a448e6abf0eb9eef9d2a45b4172aafcb1eb2bb",
  entryHashScheme: "legacy",
  leafIndex: 581,
  treeSize: 582,
};

function tamperReceiptPath(bytes: Uint8Array): Uint8Array {
  const items = decode(bytes.subarray(1), {
    allowIndefinite: false,
    useMaps: true,
  }) as unknown[];
  const unprotected = items[1] as Map<number, unknown>;
  const vdp = unprotected.get(396) as Map<number, unknown>;
  const proofs = vdp.get(-1) as Uint8Array[];
  const proof = decode(proofs[0]!, { allowIndefinite: false }) as unknown[];
  const path = proof[2] as Uint8Array[];
  path[0]![0] = path[0]![0]! ^ 1;
  proofs[0] = encode(proof, rfc8949EncodeOptions);
  return Buffer.concat([
    Uint8Array.of(0xd2),
    encode(items, rfc8949EncodeOptions),
  ]);
}

describe("capsule-anchor receipt interoperability", () => {
  it("verifies the pinned real checkpoint and witness receipt", async () => {
    expect(
      await new ReceiptVerifier(authorityKey).verify(checkpoint, receipt),
    ).toBe(true);
  });

  it("rejects every authenticated binding when tampered", async () => {
    const verifier = new ReceiptVerifier(authorityKey);
    expect(
      await new ReceiptVerifier(Uint8Array.from(authorityKey, () => 0)).verify(
        checkpoint,
        receipt,
      ),
    ).toBe(false);
    const signature = Uint8Array.from(receipt.bytes);
    signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    expect(
      await verifier.verify(checkpoint, { ...receipt, bytes: signature }),
    ).toBe(false);
    expect(
      await verifier.verify(checkpoint, {
        ...receipt,
        entryHash: `0${receipt.entryHash.slice(1)}`,
      }),
    ).toBe(false);
    expect(
      await verifier.verify(checkpoint, {
        ...receipt,
        leafIndex: receipt.leafIndex - 1,
      }),
    ).toBe(false);
    expect(
      await verifier.verify(checkpoint, {
        ...receipt,
        treeSize: receipt.treeSize + 1,
      }),
    ).toBe(false);
    expect(
      await verifier.verify(checkpoint, {
        ...receipt,
        bytes: tamperReceiptPath(receipt.bytes),
      }),
    ).toBe(false);
  });

  it("refuses a receipt forged for a pinned small-order key", async () => {
    // Under the identity as the authority key, [k]A is the identity for every
    // challenge k, so R = rB and S = r verify with no private key. Node's
    // OpenSSL accepts this on some builds (Node 22 and 24 on Linux).
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const items = decode(receipt.bytes.subarray(1), {
      allowIndefinite: false,
      useMaps: true,
    }) as unknown[];
    const nonce = 0x1234567n;
    const signature = new Uint8Array(64);
    signature.set(ed25519.Point.BASE.multiply(nonce).toBytes());
    signature.set(
      Uint8Array.from({ length: 32 }, (_, i) =>
        Number((nonce >> BigInt(8 * i)) & 0xffn),
      ),
      32,
    );
    items[3] = signature;
    const forged = Buffer.concat([
      Uint8Array.of(0xd2),
      encode(items, rfc8949EncodeOptions),
    ]);
    expect(
      await new ReceiptVerifier(identity).verify(checkpoint, {
        ...receipt,
        bytes: forged,
      }),
    ).toBe(false);
  });
});
