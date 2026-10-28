// The browser entry's checkpoint verifier in headless Chrome (vitest browser
// mode): the conformance vectors with and without crypto.subtle, one-bit
// changes, and the Ed25519 edge cases.
import { decode, encode, rfc8949EncodeOptions } from "cborg";
import { afterEach, describe, expect, it, vi } from "vitest";

import coseVectors from "../../../checkpoint-conformance-vectors/cose-vectors.json" with { type: "json" };
import checkpointVectors from "../../../checkpoint-conformance-vectors/vectors.json" with { type: "json" };
import { checkpointMetadata, verifyCheckpoint } from "../../src/browser.js";
import { verifyEd25519 } from "../../src/ed25519.js";
import {
  ed25519Cases,
  expectedMetadata,
  mutations,
  smallOrderKeyStatement,
} from "../browser-checkpoint-cases.js";

const vectors = expectedMetadata(coseVectors, checkpointVectors);
const realSubtle = globalThis.crypto.subtle;
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

it("runs in a browser", () => {
  expect((globalThis as { document?: unknown }).document).toBeDefined();
  expect(navigator.userAgent).toMatch(/Chrome/u);
});

for (const [mode, setUp] of Object.entries(modes)) {
  describe(mode, () => {
    for (const vector of vectors) {
      it(`accepts ${vector.name}`, async () => {
        const check = setUp();
        expect(await verifyCheckpoint(vector.cose)).toBe(true);
        expect(await checkpointMetadata(vector.cose)).toMatchObject(
          vector.metadata,
        );
        check();
      });

      it(`refuses every one-bit change to ${vector.name}`, async () => {
        setUp();
        const results = await Promise.all(
          mutations(vector.cose).map((cose) => verifyCheckpoint(cose)),
        );
        expect(results.every((result) => !result)).toBe(true);
      });
    }
  });
}

it("decides every Ed25519 edge case", () => {
  const differ = ed25519Cases()
    .filter(
      (edge) =>
        verifyEd25519(edge.publicKey, edge.message, edge.signature) !==
        edge.valid,
    )
    .map((edge) => edge.name);
  expect(differ).toEqual([]);
});

it("refuses a statement signed for a small-order key, which Chrome's WebCrypto Ed25519 accepts", async () => {
  const forged = smallOrderKeyStatement();
  expect(await verifyCheckpoint(forged)).toBe(false);
  expect(await checkpointMetadata(forged)).toBeUndefined();
  // Why WebCrypto's Ed25519 is not used: Chrome accepts this signature.
  const items = decode(forged.subarray(1), { useMaps: true }) as Uint8Array[];
  const key = await realSubtle.importKey(
    "raw",
    decode(items[0]!, { useMaps: true }).get(4),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const message = encode(
    ["Signature1", items[0], new Uint8Array(), items[2]],
    rfc8949EncodeOptions,
  );
  expect(
    await realSubtle.verify({ name: "Ed25519" }, key, items[3]!, message),
  ).toBe(true);
});
