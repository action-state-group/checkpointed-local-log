import { createHash, randomBytes, randomInt } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "../src/sha256.js";

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);
const reference = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("sha256 (plain implementation)", () => {
  // FIPS 180-4 / NIST CSRC SHA-256 examples.
  it.each([
    [
      "the empty message",
      ascii(""),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ],
    [
      '"abc"',
      ascii("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ],
    [
      "the 448-bit message",
      ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ],
    [
      "the 896-bit message",
      ascii(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      ),
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ],
    [
      "one million 'a'",
      new Uint8Array(1_000_000).fill(0x61),
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    ],
  ])("matches the FIPS 180-4 digest of %s", (_name, message, digest) => {
    expect(hex(sha256(message))).toBe(digest);
  });

  it("matches node:crypto at every padding boundary length", () => {
    for (const length of [
      0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129,
    ]) {
      const message = randomBytes(length);
      expect(hex(sha256(message)), `length ${length}`).toBe(reference(message));
    }
  });

  it("matches node:crypto on 1000 random messages of length 0..4096", () => {
    for (let i = 0; i < 1000; i += 1) {
      const message = randomBytes(randomInt(0, 4097));
      expect(hex(sha256(message)), `length ${message.length}`).toBe(
        reference(message),
      );
    }
  });

  it("hashes a view into a larger buffer by its own bytes only", () => {
    const backing = randomBytes(96);
    const view = new Uint8Array(backing.buffer, backing.byteOffset + 16, 40);
    expect(hex(sha256(view))).toBe(reference(view));
  });
});

describe("browser MMR hash without SubtleCrypto", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("computes the same root and verifies the same range proof as with WebCrypto", async () => {
    const leaves = Array.from({ length: 11 }, (_, i) =>
      createHash("sha256").update(`leaf ${i}`).digest(),
    );
    const build = async () => {
      const browser = await import("../src/browser.js");
      const tree = new browser.MmrTree();
      for (const leaf of leaves) await tree.append(Uint8Array.from(leaf));
      const size = BigInt(tree.nodes().length);
      const root = await tree.root();
      const proof = await browser.rangeProof(tree, 2n, 8n, size);
      const verified = await browser.verifyRange(
        root,
        size,
        2n,
        8n,
        leaves.slice(2, 9).map((l) => Uint8Array.from(l)),
        proof,
      );
      return { root: hex(root), verified };
    };
    const withWebCrypto = await build();
    vi.resetModules();
    vi.stubGlobal("crypto", undefined);
    expect(globalThis.crypto).toBeUndefined();
    const without = await build();
    expect(without).toEqual(withWebCrypto);
    expect(without.verified).toBe(true);
  });
});
