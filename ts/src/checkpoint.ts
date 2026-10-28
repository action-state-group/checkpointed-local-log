import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { canonicalJson } from "./canonical-json.js";
import {
  checkpointMetadataWith,
  encodeCanonical,
  formatTime,
  verifyCheckpointWith,
  type CheckpointCrypto,
  type CheckpointMetadata,
} from "./checkpoint-verify.js";
import { commitmentObject, rootFromPeaks } from "./mmr-node.js";
import {
  CllError,
  limits,
  validateIdentifier,
  type CheckpointSigningIdentity,
} from "./types.js";

export {
  CHECKPOINT_CONTENT_TYPE,
  type CheckpointMetadata,
} from "./checkpoint-verify.js";
export interface ConsistencyProof {
  readonly sizeA: bigint;
  readonly sizeB: bigint;
  readonly oldPeaks: readonly Uint8Array[];
  readonly witness: readonly (readonly Uint8Array[])[];
  readonly newPeaks: readonly Uint8Array[];
}
export interface CheckpointInput {
  readonly logId: string;
  readonly mmrSize: bigint;
  readonly peaks: readonly Uint8Array[];
  readonly previousSize: bigint;
  readonly previousPeaks: readonly Uint8Array[];
  readonly timestamp: Date | string;
  readonly identity: CheckpointSigningIdentity;
  readonly consistencyProof?: ConsistencyProof;
  readonly cadence?: number;
}
export interface SignedCheckpoint {
  readonly json: Uint8Array;
  readonly cose: Uint8Array;
  readonly digest: string;
  readonly logId: string;
  readonly mmrSize: bigint;
  readonly root: string;
  readonly previousSize: bigint;
  readonly previousRoot: string;
  readonly keyId: string;
  readonly timestamp: string;
}
export interface CheckpointProjectionInput {
  readonly logId: string;
  readonly mmrSize: bigint | number;
  readonly peaks: readonly Uint8Array[];
  readonly previousSize: bigint | number;
  readonly previousPeaks: readonly Uint8Array[];
  readonly keyId: string;
  readonly timestamp: string;
}

const ed25519Pkcs8Prefix = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/** Create an Ed25519 checkpoint signer from a 32-byte seed. */
export function createCheckpointIdentity(
  seed: Uint8Array,
): CheckpointSigningIdentity {
  if (seed.length !== 32) throw new TypeError("Ed25519 seed must be 32 bytes");
  const privateKey = createPrivateKey({
    key: Buffer.concat([ed25519Pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
  const der = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  return Object.freeze({
    privateKey,
    publicKey: Uint8Array.from(der.subarray(der.length - 32)),
  });
}

const taggedSign1 = (items: unknown[]): Uint8Array =>
  Buffer.concat([Uint8Array.of(0xd2), encodeCanonical(items)]);
const commitment = (peaks: readonly Uint8Array[]): Uint8Array => {
  try {
    return commitmentObject(peaks);
  } catch {
    throw new CllError("invalid", "checkpoint peak must be 32 bytes");
  }
};
const proofWire = (proof: ConsistencyProof) => ({
  size_a: Number(proof.sizeA),
  size_b: Number(proof.sizeB),
  old_peaks: proof.oldPeaks,
  witness: proof.witness,
  new_peaks: proof.newPeaks,
});

/** Canonical JSON projection whose double hash is the legacy witness entry. */
export async function checkpointProjection(input: CheckpointProjectionInput) {
  const previousSize = BigInt(input.previousSize);
  return {
    v: 1,
    kind: "mmr_checkpoint",
    log_id: input.logId,
    mmr_size: Number(input.mmrSize),
    root: Buffer.from(await rootFromPeaks(input.peaks)).toString("hex"),
    prev_size: Number(previousSize),
    prev_root:
      previousSize === 0n
        ? ""
        : Buffer.from(await rootFromPeaks(input.previousPeaks)).toString("hex"),
    key_id: input.keyId,
    timestamp: input.timestamp,
  };
}

export async function signCheckpoint(
  input: CheckpointInput,
): Promise<SignedCheckpoint> {
  validateIdentifier(input.logId);
  if (
    input.cadence !== undefined &&
    (!Number.isSafeInteger(input.cadence) || input.cadence < 1)
  )
    throw new CllError(
      "invalid",
      "checkpoint cadence must be a positive portable integer",
    );
  if (
    input.mmrSize <= 0n ||
    input.mmrSize > BigInt(Number.MAX_SAFE_INTEGER) ||
    input.previousSize < 0n ||
    input.previousSize >= input.mmrSize
  )
    throw new CllError("invalid", "invalid checkpoint sizes");
  if (input.identity.publicKey.length !== 32)
    throw new CllError("invalid", "invalid checkpoint identity");
  if (input.previousSize === 0n && input.consistencyProof !== undefined)
    throw new CllError(
      "invalid",
      "first checkpoint must not carry consistency proof",
    );
  if (
    input.previousSize > 0n &&
    (input.consistencyProof === undefined ||
      input.consistencyProof.sizeA !== input.previousSize ||
      input.consistencyProof.sizeB !== input.mmrSize)
  )
    throw new CllError(
      "invalid",
      "non-first checkpoint requires matching consistency proof",
    );
  const root = Buffer.from(await rootFromPeaks(input.peaks)).toString("hex");
  const previousRoot = Buffer.from(
    await rootFromPeaks(input.previousPeaks),
  ).toString("hex");
  const timestamp = formatTime(input.timestamp);
  const keyId = Buffer.from(input.identity.publicKey).toString("hex");
  const projection = await checkpointProjection({
    logId: input.logId,
    mmrSize: input.mmrSize,
    peaks: input.peaks,
    previousSize: input.previousSize,
    previousPeaks: input.previousPeaks,
    keyId,
    timestamp,
  });
  const json = canonicalJson(projection);
  const digest = createHash("sha256").update(json).digest("hex");
  const claims: Record<string, unknown> = {
    kind: "cll-checkpoint",
    log_size: Number(input.mmrSize),
    commitment: commitment(input.peaks),
    prev_size: Number(input.previousSize),
    prev_commitment:
      input.previousSize === 0n
        ? new Uint8Array()
        : commitment(input.previousPeaks),
    issued_at: timestamp,
  };
  if (input.cadence !== undefined) claims.cadence = input.cadence;
  if (input.consistencyProof !== undefined)
    claims.consistency_proof = proofWire(input.consistencyProof);
  const payload = encodeCanonical(claims);
  const protectedBytes = encodeCanonical(
    new Map<unknown, unknown>([
      [1, -8],
      [3, "application/cll-checkpoint+cbor"],
      [4, input.identity.publicKey],
      [
        15,
        new Map([
          [1, input.logId],
          [2, `${input.logId}#${input.mmrSize}`],
        ]),
      ],
    ]),
  );
  const sigStructure = encodeCanonical([
    "Signature1",
    protectedBytes,
    new Uint8Array(),
    payload,
  ]);
  const signature = edSign(null, sigStructure, input.identity.privateKey);
  const cose = taggedSign1([protectedBytes, new Map(), payload, signature]);
  if (cose.length > limits.checkpointPayload)
    throw new CllError("invalid", "signed checkpoint is too large");
  return {
    json,
    cose,
    digest,
    logId: input.logId,
    mmrSize: input.mmrSize,
    root,
    previousSize: input.previousSize,
    previousRoot: input.previousSize === 0n ? "" : previousRoot,
    keyId,
    timestamp,
  };
}

const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
const nodeCrypto: CheckpointCrypto = {
  hash: async (...parts) =>
    createHash("sha256").update(Buffer.concat(parts)).digest(),
  verifyEd25519: async (publicKey, message, signature) =>
    edVerify(
      null,
      message,
      createPublicKey({
        key: Buffer.concat([ed25519SpkiPrefix, publicKey]),
        format: "der",
        type: "spki",
      }),
      signature,
    ),
};

export const verifyCheckpoint = (cose: Uint8Array): Promise<boolean> =>
  verifyCheckpointWith(nodeCrypto, cose);

/** Return linkage metadata only after the complete checkpoint validates. */
export const checkpointMetadata = (
  cose: Uint8Array,
): Promise<CheckpointMetadata | undefined> =>
  checkpointMetadataWith(nodeCrypto, cose);

/** Return the RFC 9162 checkpoint entry hash after full checkpoint validation. */
export async function checkpointEntryHash(
  cose: Uint8Array,
): Promise<Uint8Array | undefined> {
  const metadata = await checkpointMetadata(cose);
  if (metadata === undefined) return undefined;
  const projection = await checkpointProjection({
    logId: metadata.logId,
    mmrSize: metadata.size,
    peaks: metadata.peaks,
    previousSize: metadata.previousSize,
    previousPeaks: metadata.previousPeaks,
    keyId: metadata.keyId,
    timestamp: metadata.timestamp,
  });
  return createHash("sha256")
    .update(createHash("sha256").update(canonicalJson(projection)).digest())
    .digest();
}
