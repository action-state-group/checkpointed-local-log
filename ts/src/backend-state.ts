import { cloneCll, cloneEntry, cloneWitness } from "./clone.js";
import { leafCount } from "./mmr.js";
import {
  CllError,
  limits,
  validateIdentifier,
  type AppendInput,
  type AppendResult,
  type CllEntry,
  type CllState,
  type WitnessState,
} from "./types.js";

const same = (left: Uint8Array, right: Uint8Array): boolean =>
  Buffer.from(left).equals(Buffer.from(right));

const sameList = (
  left: readonly Uint8Array[],
  right: readonly Uint8Array[],
): boolean =>
  left.length === right.length &&
  left.every((value, index) => same(value, right[index]!));

export const witnessKey = (
  value: Pick<WitnessState, "witnessId" | "checkpointSize">,
): string => `${value.witnessId}\0${value.checkpointSize}`;

export const addedWitnesses = (
  before: readonly WitnessState[],
  after: readonly WitnessState[],
): readonly WitnessState[] => {
  const existing = new Set(before.map(witnessKey));
  return after.filter((item) => !existing.has(witnessKey(item)));
};

export function validateAppendInput(input: AppendInput): void {
  if (
    input.value.length !== limits.entryBytes ||
    !Number.isFinite(input.appendedAt.valueOf())
  )
    throw new CllError(
      "invalid",
      "entry must have 32 bytes and a valid append time",
    );
}

export function validateEntryValue(value: Uint8Array): void {
  if (value.length !== limits.entryBytes)
    throw new CllError("invalid", "entry value must be 32 bytes");
}

export function validateEntryScan(afterSeq: bigint, limit: number): void {
  if (
    afterSeq < 0n ||
    afterSeq > BigInt(Number.MAX_SAFE_INTEGER) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > limits.scanMax
  )
    throw new CllError("invalid", "invalid entry scan");
}

const validTime = (value: Date): boolean => Number.isFinite(value.valueOf());

/** Rejects a witness key outside the identifier rules or with size 0. */
export function validateWitnessKey(
  witnessId: string,
  checkpointSize: bigint,
): void {
  validateIdentifier(witnessId);
  if (checkpointSize <= 0n || checkpointSize > 0xffffffffffffffffn)
    throw new CllError("invalid", "witness checkpoint size is invalid");
}

/** Applies the contract's witness rules (docs/backend-contract.md). */
export function validateWitness(
  value: WitnessState,
  code: "invalid" | "corrupt" = "invalid",
): void {
  const fail = (message: string): never => {
    throw new CllError(code, message);
  };
  try {
    validateWitnessKey(value.witnessId, value.checkpointSize);
  } catch {
    fail("witness key is invalid");
  }
  if (
    value.checkpoint.length < 1 ||
    value.checkpoint.length > limits.checkpointPayload ||
    !validTime(value.nextAttemptAt) ||
    !Number.isInteger(value.attempts) ||
    value.attempts < 0 ||
    value.attempts > 0xffffffff ||
    typeof value.permanent !== "boolean" ||
    (value.lastError !== undefined &&
      Buffer.byteLength(value.lastError) > limits.reason)
  )
    fail("witness state is invalid");
  if (value.receipt === undefined) {
    if (
      value.entryHash !== undefined ||
      value.entryHashScheme !== undefined ||
      value.leafIndex !== undefined ||
      value.treeSize !== undefined
    )
      fail("witness receipt metadata needs a receipt");
    return;
  }
  if (value.receipt.length < 1 || value.receipt.length > limits.receipt)
    fail("witness receipt is invalid");
  if (value.entryHash !== undefined && !/^[0-9a-f]{64}$/u.test(value.entryHash))
    fail("witness entry hash is invalid");
  if (value.entryHashScheme !== undefined && value.entryHashScheme !== "legacy")
    fail("witness entry hash scheme is invalid");
  for (const position of [value.leafIndex, value.treeSize])
    if (
      position !== undefined &&
      (!Number.isSafeInteger(position) || position < 0)
    )
      fail("witness receipt position is invalid");
}

/** Applies the contract's structural rules for one complete CLL state. */
export function validateCllState(
  value: CllState,
  code: "invalid" | "corrupt" = "invalid",
): void {
  const fail = (message: string): never => {
    throw new CllError(code, message);
  };
  if (value.size !== BigInt(value.nodes.length))
    fail("CLL size does not match nodes");
  if (value.nodes.some((node) => node.length !== limits.entryBytes))
    fail("node has wrong width");
  if (leafCount(value.size) !== value.indexedSeq)
    fail("CLL nodes do not form the indexed MMR");
  if (value.firstPendingAt !== undefined && !validTime(value.firstPendingAt))
    fail("pending time is invalid");
  const tuple = [
    value.checkpoint,
    value.checkpointSize,
    value.checkpointIndexedSeq,
    value.checkpointPeaks,
  ].filter((item) => item !== undefined).length;
  if (tuple !== 0 && tuple !== 4) fail("checkpoint state is incomplete");
  if (tuple === 4) {
    const bytes = value.checkpoint!;
    if (
      bytes.length < 1 ||
      bytes.length > limits.checkpointPayload ||
      value.checkpointSize! <= 0n ||
      value.checkpointSize! > value.size ||
      value.checkpointIndexedSeq! < 0n ||
      value.checkpointIndexedSeq! > value.indexedSeq ||
      value.checkpointPeaks!.some((peak) => peak.length !== limits.entryBytes)
    )
      fail("checkpoint state is invalid");
  }
  const seen = new Set<string>();
  for (const witness of value.witnesses) {
    validateWitness(witness, code);
    const key = witnessKey(witness);
    if (seen.has(key)) fail("duplicate witness key");
    seen.add(key);
  }
}

const emptyCll = (witnesses: readonly WitnessState[] = []): CllState => ({
  size: 0n,
  nodes: [],
  indexedSeq: 0n,
  witnesses,
});

/** Apply the shared CLL transition rules without requiring entry state. */
export function applyCll(
  current: CllState,
  expectedSize: bigint,
  expectedCheckpoint: Uint8Array | undefined,
  next: CllState,
): CllState {
  const state = new BackendState(current);
  state.commitCll(expectedSize, expectedCheckpoint, next);
  return state.cll();
}

/** Select due witnesses through the same rules used by in-memory backends. */
export function selectPendingWitnesses(
  witnesses: readonly WitnessState[],
  now: Date,
  limit: number,
): readonly WitnessState[] {
  const state = new BackendState(emptyCll(witnesses));
  return state.pendingWitnesses(now, limit);
}

/** Apply one witness compare-and-set transition without loading unrelated rows. */
export function applyWitness(
  current: WitnessState,
  expectedAttempts: number,
  next: WitnessState,
): WitnessState {
  const state = new BackendState(emptyCll([current]));
  state.commitWitness(expectedAttempts, next);
  return state.getWitness(next.witnessId, next.checkpointSize)!;
}

/** Numeric checkpoint size, then witness ID in byte order. */
export const comparePending = (a: WitnessState, b: WitnessState): number =>
  a.checkpointSize !== b.checkpointSize
    ? a.checkpointSize < b.checkpointSize
      ? -1
      : 1
    : Buffer.compare(Buffer.from(a.witnessId), Buffer.from(b.witnessId));

/** Shared invariant engine. Durable backends compose it and persist every mutation. */
export class BackendState {
  private entries_: CllEntry[] = [];
  private byValue = new Map<string, CllEntry>();
  private cll_: CllState = {
    size: 0n,
    nodes: [],
    indexedSeq: 0n,
    witnesses: [],
  };

  public constructor(cll?: CllState) {
    if (cll !== undefined) this.cll_ = cloneCll(cll);
  }

  public entries(): readonly CllEntry[] {
    return this.entries_.map(cloneEntry);
  }

  public cll(): CllState {
    return cloneCll(this.cll_);
  }

  /**
   * Roll back an append or CLL/witness commit when external persistence fails.
   * This remains O(1) because entries only append and each CLL mutation replaces
   * `cll_`; mutation methods must preserve those invariants.
   */
  public async persistMutation<T>(
    operation: () => T,
    persist: (result: T) => Promise<void>,
  ): Promise<T> {
    const entryCount = this.entries_.length;
    const cll = this.cll_;
    try {
      const result = operation();
      await persist(result);
      return result;
    } catch (error) {
      while (this.entries_.length > entryCount) {
        const removed = this.entries_.pop()!;
        this.byValue.delete(Buffer.from(removed.value).toString("hex"));
      }
      this.cll_ = cll;
      throw error;
    }
  }

  public append(input: AppendInput): AppendResult {
    validateAppendInput(input);
    const key = Buffer.from(input.value).toString("hex");
    const existing = this.byValue.get(key);
    if (existing !== undefined)
      return { entry: cloneEntry(existing), outcome: "idempotent" };
    const entry: CllEntry = {
      seq: BigInt(this.entries_.length + 1),
      value: Uint8Array.from(input.value),
      appendedAt: new Date(Math.trunc(input.appendedAt.valueOf())),
    };
    this.entries_.push(entry);
    this.byValue.set(key, entry);
    return { entry: cloneEntry(entry), outcome: "inserted" };
  }

  public getEntry(value: Uint8Array): CllEntry {
    validateEntryValue(value);
    const entry = this.byValue.get(Buffer.from(value).toString("hex"));
    if (entry === undefined) throw new CllError("not_found", "entry not found");
    return cloneEntry(entry);
  }

  public scanEntries(afterSeq: bigint, limit: number): readonly CllEntry[] {
    validateEntryScan(afterSeq, limit);
    const start =
      afterSeq >= BigInt(this.entries_.length)
        ? this.entries_.length
        : Number(afterSeq);
    return this.entries_.slice(start, start + limit).map(cloneEntry);
  }

  /**
   * Compare-and-set in the contract's order: the expected values first
   * (contention), then the structure of `next` (invalid), then the
   * transition rules (contention).
   */
  public commitCll(
    expectedSize: bigint,
    expectedCheckpoint: Uint8Array | undefined,
    next: CllState,
  ): void {
    const current = this.cll_;
    if (current.size !== expectedSize)
      throw new CllError("contention", "CLL state changed");
    if (
      (expectedCheckpoint === undefined) !==
        (current.checkpoint === undefined) ||
      (expectedCheckpoint !== undefined &&
        current.checkpoint !== undefined &&
        !same(expectedCheckpoint, current.checkpoint))
    )
      throw new CllError("contention", "CLL checkpoint changed");
    validateCllState(next);
    if (
      next.size < current.size ||
      next.indexedSeq < current.indexedSeq ||
      current.nodes.some((node, index) => !same(node, next.nodes[index]!))
    )
      throw new CllError("invalid", "CLL state is not append-only");
    if (current.checkpoint !== undefined) {
      if (next.checkpoint === undefined)
        throw new CllError("contention", "checkpoint state cannot be removed");
      if (
        next.checkpointSize! < current.checkpointSize! ||
        next.checkpointIndexedSeq! < current.checkpointIndexedSeq!
      )
        throw new CllError("contention", "checkpoint cannot move backward");
      if (
        next.checkpointSize === current.checkpointSize &&
        (!same(next.checkpoint, current.checkpoint) ||
          next.checkpointIndexedSeq !== current.checkpointIndexedSeq ||
          !sameList(next.checkpointPeaks!, current.checkpointPeaks!))
      )
        throw new CllError(
          "contention",
          "checkpoint already exists at this CLL size",
        );
    }
    const existing = new Map(
      current.witnesses.map((item) => [witnessKey(item), item]),
    );
    for (const witness of next.witnesses) {
      const stored = existing.get(witnessKey(witness));
      if (stored !== undefined && !same(stored.checkpoint, witness.checkpoint))
        throw new CllError(
          "contention",
          "witness delivery already exists for another checkpoint",
        );
    }
    this.cll_ = cloneCll({
      ...next,
      witnesses: [
        ...current.witnesses,
        ...next.witnesses.filter((item) => !existing.has(witnessKey(item))),
      ],
    });
  }

  public pendingWitnesses(now: Date, limit: number): readonly WitnessState[] {
    if (
      !validTime(now) ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > limits.witnesses
    )
      throw new CllError("invalid", "invalid pending witness query");
    return this.cll_.witnesses
      .filter(
        (item) =>
          item.receipt === undefined &&
          !item.permanent &&
          item.nextAttemptAt <= now,
      )
      .sort(comparePending)
      .slice(0, limit)
      .map(cloneWitness);
  }

  public getWitness(
    witnessId: string,
    checkpointSize: bigint,
  ): WitnessState | undefined {
    validateWitnessKey(witnessId, checkpointSize);
    const value = this.cll_.witnesses.find(
      (item) => witnessKey(item) === witnessKey({ witnessId, checkpointSize }),
    );
    return value === undefined ? undefined : cloneWitness(value);
  }

  public commitWitness(expectedAttempts: number, next: WitnessState): void {
    validateWitness(next);
    const index = this.cll_.witnesses.findIndex(
      (item) => witnessKey(item) === witnessKey(next),
    );
    if (index < 0 || this.cll_.witnesses[index]!.attempts !== expectedAttempts)
      throw new CllError("contention", "witness state changed");
    if (!same(this.cll_.witnesses[index]!.checkpoint, next.checkpoint))
      throw new CllError("contention", "witness checkpoint changed");
    const witnesses = [...this.cll_.witnesses];
    witnesses[index] = cloneWitness(next);
    this.cll_ = { ...this.cll_, witnesses };
  }
}
