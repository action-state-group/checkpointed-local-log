// Browser condition: MMR substrate only. Storage, checkpoints, and witnesses require Node.
import {
  MmrTree as CoreMmrTree,
  commitmentObject,
  consistencyProof,
  inclusionProof,
  leafCount,
  rangeProof,
  rootFromPeaks as coreRootFromPeaks,
  verifyConsistency as coreVerifyConsistency,
  verifyHexInclusion as coreVerifyHexInclusion,
  verifyInclusionValue as coreVerifyInclusionValue,
  verifyRange as coreVerifyRange,
  type MmrConsistencyProof,
  type MmrHash,
  type MmrInclusionProof,
  type MmrRangeProof,
  type MmrStructuredConsistencyProof,
} from "./mmr.js";
import { sha256 } from "./sha256.js";

const join = (...parts: readonly Uint8Array[]): Uint8Array => {
  const value = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    value.set(part, offset);
    offset += part.length;
  }
  return value;
};
type Subtle = {
  digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer>;
};
// WebCrypto's digest where the page has it; SubtleCrypto exists only in a
// secure context, so a page in a non-secure or opaque origin (an http: or
// data: page, some apps' attachment viewers) hashes with the plain
// implementation instead. Both are SHA-256.
const hash: MmrHash = async (...parts) => {
  const subtle = (globalThis as { crypto?: { subtle?: Subtle } }).crypto
    ?.subtle;
  return typeof subtle?.digest === "function"
    ? new Uint8Array(await subtle.digest("SHA-256", join(...parts)))
    : sha256(join(...parts));
};

export {
  commitmentObject,
  consistencyProof,
  inclusionProof,
  leafCount,
  rangeProof,
};
export type {
  MmrConsistencyProof,
  MmrHash,
  MmrInclusionProof,
  MmrRangeProof,
  MmrStructuredConsistencyProof,
};
export class MmrTree extends CoreMmrTree {
  public constructor(nodes: readonly Uint8Array[] = []) {
    super(hash, nodes);
  }
}
export const rootFromPeaks = (peaks: readonly Uint8Array[]) =>
  coreRootFromPeaks(hash, peaks);
export const verifyInclusionValue = (
  root: Uint8Array,
  size: bigint,
  leafIndex: bigint,
  value: Uint8Array,
  proof: readonly Uint8Array[],
) => coreVerifyInclusionValue(hash, root, size, leafIndex, value, proof);
export const verifyHexInclusion = (
  root: Uint8Array,
  size: bigint,
  leafIndex: bigint,
  identity: string,
  proof: readonly Uint8Array[],
) => coreVerifyHexInclusion(hash, root, size, leafIndex, identity, proof);
export const verifyConsistency = (
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: MmrConsistencyProof,
) => coreVerifyConsistency(hash, oldRoot, newRoot, proof);
export const verifyRange = (
  root: Uint8Array,
  size: bigint,
  fromIndex: bigint,
  toIndex: bigint,
  bodyDigests: readonly Uint8Array[],
  proof: MmrRangeProof,
) => coreVerifyRange(hash, root, size, fromIndex, toIndex, bodyDigests, proof);
