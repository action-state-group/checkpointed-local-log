import { createHash } from "node:crypto";
import { encode, rfc8949EncodeOptions } from "cborg";
import {
  CborMap,
  CborTag,
  type CborValue,
  decodeReceiptItem,
} from "./cbor-strict.js";
import { checkpointEntryHash } from "./checkpoint.js";
import { verifyEd25519 } from "./ed25519.js";
import { limits } from "./types.js";
import type { WitnessReceipt } from "./witness.js";

const encodeCanonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);
const sha = (...parts: readonly Uint8Array[]): Uint8Array =>
  createHash("sha256").update(Buffer.concat(parts)).digest();
const nodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array =>
  sha(Uint8Array.of(1), left, right);
const MAX_TREE_SIZE = 1n << 62n;
const MAX_INCLUSION_PROOFS = 16;
const ALG = 1n;
const CRIT = 2n;
const CWT_CLAIMS = 15n;
const VDS = 395n;
const VDP = 396n;
// Protected labels this verifier processes, for RFC 9052 crit enforcement.
const UNDERSTOOD = new Set([ALG, CRIT, VDS, CWT_CLAIMS]);

const largestPowerBelow = (value: bigint): bigint => {
  let power = 1n;
  while (power * 2n < value) power *= 2n;
  return power;
};
const expectedPath = (size: bigint, index: bigint): number => {
  let count = 0;
  let nodes = size;
  let position = index;
  while (nodes > 1n) {
    count += 1;
    const split = largestPowerBelow(nodes);
    if (position < split) nodes = split;
    else {
      nodes -= split;
      position -= split;
    }
  }
  return count;
};

interface InclusionProof {
  readonly size: bigint;
  readonly index: bigint;
  readonly path: readonly Uint8Array[];
}

/**
 * CBOR [tree_size, leaf_index, [audit_path...]], decoded under the receipt
 * encoding rule as the message around it is.
 */
function inclusionProof(blob: Uint8Array): InclusionProof {
  const value = decodeReceiptItem(blob, false);
  if (!Array.isArray(value) || value.length !== 3)
    throw new SyntaxError(
      "inclusion proof must be [tree_size, leaf_index, [path]]",
    );
  const [size, index, path] = value as readonly CborValue[];
  if (typeof size !== "bigint" || typeof index !== "bigint")
    throw new SyntaxError("inclusion proof sizes must be integers");
  if (
    !Array.isArray(path) ||
    !(path as readonly CborValue[]).every(
      (node) => node instanceof Uint8Array && node.length === 32,
    )
  )
    throw new SyntaxError("inclusion proof path nodes must be 32 bytes");
  if (index < 0n || index >= size || size > MAX_TREE_SIZE)
    throw new SyntaxError("invalid tree size or leaf index");
  if (path.length !== expectedPath(size, index))
    throw new SyntaxError("invalid inclusion proof path length");
  return { size, index, path: path as Uint8Array[] };
}

function proofRoot(entry: Uint8Array, proof: InclusionProof): Uint8Array {
  const siblings = [...proof.path];
  const leaf = sha(Uint8Array.of(0), entry);
  const fold = (nodes: bigint, position: bigint): Uint8Array => {
    if (nodes === 1n) return leaf;
    // inclusionProof checked the path length, so a sibling is always left.
    const sibling = siblings.pop()!;
    const split = largestPowerBelow(nodes);
    if (position < split) return nodeHash(fold(split, position), sibling);
    return nodeHash(sibling, fold(nodes - split, position - split));
  };
  return fold(proof.size, proof.index);
}

/** RFC 9052 section 3.1: crit names present, understood protected labels. */
function criticalUnderstood(headers: CborMap): boolean {
  if (!headers.has(CRIT)) return true;
  const crit = headers.get(CRIT);
  return (
    Array.isArray(crit) &&
    crit.length > 0 &&
    (crit as readonly CborValue[]).every(
      (label) =>
        typeof label === "bigint" &&
        label >= 0n &&
        UNDERSTOOD.has(label) &&
        headers.has(label),
    )
  );
}

/** Offline RFC 9162 receipt verifier under a pinned Ed25519 authority key. */
export class ReceiptVerifier {
  private readonly publicKey: Uint8Array;
  public constructor(publicKey: Uint8Array) {
    if (publicKey.length !== 32)
      throw new TypeError("pinned Ed25519 authority key must be 32 bytes");
    this.publicKey = Uint8Array.from(publicKey);
  }

  public async verify(
    checkpoint: Uint8Array,
    receipt: WitnessReceipt,
  ): Promise<boolean> {
    try {
      if (
        receipt.bytes.length === 0 ||
        receipt.bytes.length > limits.receipt ||
        receipt.entryHashScheme !== "legacy" ||
        typeof receipt.entryHash !== "string" ||
        !/^[0-9a-f]{64}$/u.test(receipt.entryHash) ||
        !Number.isSafeInteger(receipt.treeSize) ||
        !Number.isSafeInteger(receipt.leafIndex)
      )
        return false;
      const entry = await checkpointEntryHash(checkpoint);
      if (
        entry === undefined ||
        Buffer.from(entry).toString("hex") !== receipt.entryHash
      )
        return false;
      // agent-action-capsule's VerifyCOSEReceipt profile, so both accept the
      // same receipts (checkpoint-conformance-vectors/receipt-vectors.json).
      const message = decodeReceiptItem(receipt.bytes, true);
      if (!(message instanceof CborTag) || message.tag !== 18n) return false;
      const items = message.value;
      if (
        !Array.isArray(items) ||
        items.length !== 4 ||
        !(items[0] instanceof Uint8Array) ||
        !(items[1] instanceof CborMap) ||
        // An attached payload binds nothing: the signature must cover the
        // root rebuilt from the proof.
        items[2] !== null ||
        !(items[3] instanceof Uint8Array)
      )
        return false;
      const [protectedBytes, unprotected, , signature] = items as [
        Uint8Array,
        CborMap,
        null,
        Uint8Array,
      ];
      const protectedHeaders =
        protectedBytes.length === 0
          ? new CborMap([])
          : decodeReceiptItem(protectedBytes, false);
      if (
        !(protectedHeaders instanceof CborMap) ||
        protectedHeaders.get(ALG) !== -8n ||
        protectedHeaders.get(VDS) !== 1n ||
        !criticalUnderstood(protectedHeaders)
      )
        return false;
      const vdp = unprotected.get(VDP);
      if (!(vdp instanceof CborMap)) return false;
      const blobs = vdp.get(-1n);
      if (
        !Array.isArray(blobs) ||
        blobs.length === 0 ||
        blobs.length > MAX_INCLUSION_PROOFS ||
        !(blobs as readonly CborValue[]).every(
          (blob) => blob instanceof Uint8Array,
        )
      )
        return false;
      // Decode every proof before verifying any: a valid proof must not hide
      // a malformed later entry in this unauthenticated array.
      const proofs = (blobs as readonly Uint8Array[]).map(inclusionProof);
      for (const proof of proofs) {
        const root = proofRoot(entry, proof);
        // The strict verifier, not Node's OpenSSL, which on some builds
        // accepts a signature by a small-order key that needs no private key.
        if (
          !verifyEd25519(
            this.publicKey,
            encodeCanonical([
              "Signature1",
              protectedBytes,
              new Uint8Array(),
              root,
            ]),
            signature,
          )
        )
          continue;
        // The runner stores the response's position, so it must be the one
        // the verified proof carries.
        return (
          proof.size === BigInt(receipt.treeSize!) &&
          proof.index === BigInt(receipt.leafIndex!)
        );
      }
      return false;
    } catch {
      return false;
    }
  }
}
