// checkpoint-conformance-vectors/ed25519-vectors.json, shared by every
// implementation: Ed25519 inputs a checkpoint verifier must decide one way,
// including the small-order and non-canonical ones platform libraries accept.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import * as browser from "../src/browser.js";
import { verifyEd25519 } from "../src/ed25519.js";
import * as node from "../src/index.js";
import { fromHex } from "./browser-checkpoint-cases.js";

interface Ed25519Vectors {
  readonly ed25519_cases: readonly {
    readonly name: string;
    readonly public_key_hex: string;
    readonly message_hex: string;
    readonly signature_hex: string;
    readonly valid: boolean;
  }[];
  readonly cose_cases: readonly {
    readonly name: string;
    readonly cose_hex: string;
    readonly valid: boolean;
  }[];
}

const vectors = JSON.parse(
  readFileSync(
    resolve(
      process.env.CLL_ROOT ?? "..",
      "checkpoint-conformance-vectors",
      "ed25519-vectors.json",
    ),
    "utf8",
  ),
) as Ed25519Vectors;

describe("Ed25519 vectors", () => {
  it("decides every raw case", () => {
    const results = vectors.ed25519_cases.map((edge) => ({
      name: edge.name,
      valid: verifyEd25519(
        fromHex(edge.public_key_hex),
        fromHex(edge.message_hex),
        fromHex(edge.signature_hex),
      ),
    }));
    expect(results).toEqual(
      vectors.ed25519_cases.map(({ name, valid }) => ({ name, valid })),
    );
  });

  it("decides every checkpoint statement the same in both entries", async () => {
    const results = await Promise.all(
      vectors.cose_cases.map(async (statement) => {
        const cose = fromHex(statement.cose_hex);
        return {
          name: statement.name,
          node: await node.verifyCheckpoint(cose),
          browser: await browser.verifyCheckpoint(cose),
        };
      }),
    );
    expect(results).toEqual(
      vectors.cose_cases.map(({ name, valid }) => ({
        name,
        node: valid,
        browser: valid,
      })),
    );
  });
});
