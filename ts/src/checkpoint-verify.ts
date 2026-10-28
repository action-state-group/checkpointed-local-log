// Checkpoint verification shared by the Node and browser entries. It uses no
// Node API: the entries pass in their SHA-256 and Ed25519 primitives, so every
// structural check below runs identically in both and the entries can differ
// only inside those two primitives.
import { decode, encode, rfc8949EncodeOptions } from "cborg";
import {
  leafCount,
  rootFromPeaks,
  verifyConsistency,
  type MmrHash,
} from "./mmr.js";
import { CllError, limits, validateIdentifier } from "./types.js";

export const CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor";

/** Ed25519 verification of `signature` over `message` by a raw 32-byte key. */
export type Ed25519Verify = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
) => Promise<boolean>;

export interface CheckpointCrypto {
  readonly hash: MmrHash;
  readonly verifyEd25519: Ed25519Verify;
}

export interface CheckpointMetadata {
  readonly logId: string;
  readonly size: bigint;
  readonly peaks: readonly Uint8Array[];
  readonly previousSize: bigint;
  readonly previousPeaks: readonly Uint8Array[];
  readonly root: string;
  readonly previousRoot: string;
  readonly keyId: string;
  readonly timestamp: string;
  readonly cadence?: number;
}

export const encodeCanonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

export const formatTime = (value: Date | string): string => {
  if (value instanceof Date) {
    if (Number.isNaN(value.valueOf()))
      throw new CllError("invalid", "invalid checkpoint timestamp");
    return value
      .toISOString()
      .replace(/\.000Z$/u, "Z")
      .replace(/(\.\d*?[1-9])0+Z$/u, "$1Z");
  }
  const match =
    /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/u.exec(
      value,
    );
  if (match === null)
    throw new CllError("invalid", "invalid checkpoint timestamp");
  const fraction = (match[2] ?? "").padEnd(9, "0");
  const parsed = new Date(`${match[1]}.${fraction.slice(0, 3)}${match[3]}`);
  if (Number.isNaN(parsed.valueOf()))
    throw new CllError("invalid", "invalid checkpoint timestamp");
  const trimmed = fraction.replace(/0+$/u, "");
  return `${parsed.toISOString().slice(0, 19)}${trimmed === "" ? "" : `.${trimmed}`}Z`;
};

export async function verifyCheckpointWith(
  crypto: CheckpointCrypto,
  cose: Uint8Array,
): Promise<boolean> {
  try {
    if (
      cose.length < 2 ||
      cose.length > limits.checkpointPayload ||
      cose[0] !== 0xd2
    )
      return false;
    const items = decode(cose.subarray(1), {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
      useMaps: true,
    }) as unknown[];
    if (
      !Array.isArray(items) ||
      items.length !== 4 ||
      !(items[0] instanceof Uint8Array) ||
      !(items[1] instanceof Map) ||
      items[1].size !== 0 ||
      !(items[2] instanceof Uint8Array) ||
      !(items[3] instanceof Uint8Array)
    )
      return false;
    const headers = decode(items[0], {
      allowIndefinite: false,
      useMaps: true,
    }) as unknown;
    if (!(headers instanceof Map)) return false;
    const kid = headers.get(4);
    const cwt = headers.get(15);
    if (
      headers.size !== 4 ||
      headers.get(1) !== -8 ||
      headers.get(3) !== CHECKPOINT_CONTENT_TYPE ||
      !(kid instanceof Uint8Array) ||
      kid.length !== 32 ||
      !(cwt instanceof Map) ||
      cwt.size !== 2
    )
      return false;
    const logId = cwt.get(1);
    const subject = cwt.get(2);
    if (typeof logId !== "string" || typeof subject !== "string") return false;
    validateIdentifier(logId);

    const claims = decode(items[2], {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
      useMaps: true,
    }) as unknown;
    if (
      !(claims instanceof Map) ||
      !bytesEqual(encodeCanonical(claims), items[2])
    )
      return false;
    const allowedClaims = new Set([
      "kind",
      "log_size",
      "commitment",
      "prev_size",
      "prev_commitment",
      "issued_at",
      "cadence",
      "consistency_proof",
    ]);
    if (
      claims.size < 6 ||
      claims.size > 8 ||
      [...claims.keys()].some(
        (key) => typeof key !== "string" || !allowedClaims.has(key),
      ) ||
      claims.get("kind") !== "cll-checkpoint"
    )
      return false;
    const logSize = claims.get("log_size");
    const previousSize = claims.get("prev_size");
    const issuedAt = claims.get("issued_at");
    if (
      !Number.isSafeInteger(logSize) ||
      (logSize as number) < 1 ||
      !Number.isSafeInteger(previousSize) ||
      (previousSize as number) < 0 ||
      (previousSize as number) >= (logSize as number) ||
      typeof issuedAt !== "string" ||
      formatTime(issuedAt) !== issuedAt ||
      subject !== `${logId}#${logSize as number}`
    )
      return false;
    const decodePeaks = (value: unknown): Uint8Array[] | undefined => {
      if (!(value instanceof Uint8Array)) return undefined;
      const decoded = decode(value, {
        allowIndefinite: false,
        coerceUndefinedToNull: false,
      }) as unknown;
      if (
        !Array.isArray(decoded) ||
        decoded.some(
          (peak) => !(peak instanceof Uint8Array) || peak.length !== 32,
        ) ||
        !bytesEqual(encodeCanonical(decoded), value)
      )
        return undefined;
      return decoded as Uint8Array[];
    };
    const peaks = decodePeaks(claims.get("commitment"));
    if (peaks === undefined) return false;
    const leaves = leafCount(BigInt(logSize as number));
    if (leaves === undefined) return false;
    let peakCount = 0;
    for (let value = leaves; value !== 0n; value >>= 1n)
      peakCount += Number(value & 1n);
    if (peaks.length !== peakCount) return false;

    const previousCommitment = claims.get("prev_commitment");
    if (!(previousCommitment instanceof Uint8Array)) return false;
    if ((previousSize as number) === 0) {
      if (previousCommitment.length !== 0 || claims.has("consistency_proof"))
        return false;
    } else {
      const previousPeaks = decodePeaks(previousCommitment);
      const proof = claims.get("consistency_proof");
      if (previousPeaks === undefined || !(proof instanceof Map)) return false;
      const sizeA = proof.get("size_a");
      const sizeB = proof.get("size_b");
      const oldPeaks = proof.get("old_peaks");
      const witness = proof.get("witness");
      const newPeaks = proof.get("new_peaks");
      if (
        proof.size !== 5 ||
        sizeA !== previousSize ||
        sizeB !== logSize ||
        !Array.isArray(oldPeaks) ||
        !Array.isArray(newPeaks) ||
        !Array.isArray(witness) ||
        oldPeaks.some(
          (peak) => !(peak instanceof Uint8Array) || peak.length !== 32,
        ) ||
        newPeaks.some(
          (peak) => !(peak instanceof Uint8Array) || peak.length !== 32,
        ) ||
        witness.some(
          (path) =>
            !Array.isArray(path) ||
            path.some(
              (hash) => !(hash instanceof Uint8Array) || hash.length !== 32,
            ),
        ) ||
        !bytesEqual(
          encodeCanonical(oldPeaks),
          encodeCanonical(previousPeaks),
        ) ||
        !bytesEqual(encodeCanonical(newPeaks), encodeCanonical(peaks)) ||
        !(await verifyConsistency(
          crypto.hash,
          await rootFromPeaks(crypto.hash, previousPeaks),
          await rootFromPeaks(crypto.hash, peaks),
          {
            oldSize: BigInt(previousSize as number),
            newSize: BigInt(logSize as number),
            oldPeaks: oldPeaks as Uint8Array[],
            witness: witness as Uint8Array[][],
            newPeaks: newPeaks as Uint8Array[],
          },
        ))
      )
        return false;
    }
    if (claims.has("cadence")) {
      const cadence = claims.get("cadence");
      if (!Number.isSafeInteger(cadence) || (cadence as number) < 1)
        return false;
    }
    // Only an exact `true` passes, so a primitive that returns anything else
    // cannot make a statement verify.
    return (
      (await crypto.verifyEd25519(
        kid,
        encodeCanonical(["Signature1", items[0], new Uint8Array(), items[2]]),
        items[3],
      )) === true
    );
  } catch {
    return false;
  }
}

/** Return linkage metadata only after the complete checkpoint validates. */
export async function checkpointMetadataWith(
  crypto: CheckpointCrypto,
  cose: Uint8Array,
): Promise<CheckpointMetadata | undefined> {
  if (!(await verifyCheckpointWith(crypto, cose))) return undefined;
  const items = decode(cose.subarray(1), {
    allowIndefinite: false,
    coerceUndefinedToNull: false,
    useMaps: true,
  }) as unknown[];
  const headers = decode(items[0] as Uint8Array, {
    allowIndefinite: false,
    useMaps: true,
  }) as Map<number, unknown>;
  const claims = decode(items[2] as Uint8Array, {
    allowIndefinite: false,
    coerceUndefinedToNull: false,
    useMaps: true,
  }) as Map<string, unknown>;
  const decodeCommittedPeaks = (value: Uint8Array): Uint8Array[] =>
    decode(value, {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
    }) as Uint8Array[];
  const cwt = headers.get(15) as Map<number, unknown>;
  const previousSize = BigInt(claims.get("prev_size") as number);
  const previousCommitment = claims.get("prev_commitment") as Uint8Array;
  const peaks = decodeCommittedPeaks(claims.get("commitment") as Uint8Array);
  const previousPeaks =
    previousSize === 0n ? [] : decodeCommittedPeaks(previousCommitment);
  return {
    logId: cwt.get(1) as string,
    size: BigInt(claims.get("log_size") as number),
    peaks,
    previousSize,
    previousPeaks,
    root: toHex(await rootFromPeaks(crypto.hash, peaks)),
    previousRoot:
      previousSize === 0n
        ? ""
        : toHex(await rootFromPeaks(crypto.hash, previousPeaks)),
    keyId: toHex(headers.get(4) as Uint8Array),
    timestamp: claims.get("issued_at") as string,
    ...(claims.has("cadence")
      ? { cadence: claims.get("cadence") as number }
      : {}),
  };
}
