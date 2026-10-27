/**
 * Runs the language-neutral CLL backend conformance vectors
 * (backend-conformance-vectors/ in the repository, pinned here) against any
 * backend, built-in or user-supplied. The vectors implement
 * docs/backend-contract.md.
 *
 * The runner depends on no test framework: map each case onto one test.
 *
 * ```ts
 * for (const item of conformanceCases({ open: () => new MemoryStore() }))
 *   it.skipIf(item.skip !== undefined)(item.name, item.run);
 * ```
 */
import vectors from "./conformance/vectors.json" with { type: "json" };
import { cllToWire, entryToWire, witnessToWire } from "./serde.js";
import type {
  CheckpointStateStore,
  CllError,
  CllState,
  EntryCounter,
  EntryStore,
  WitnessState,
  WitnessStateStore,
} from "./types.js";

export interface ConformanceConfig {
  /** Returns a fresh, empty backend for one case. */
  open(): unknown;
  /**
   * Closes `current` and opens the same durable state again. Omit it for a
   * backend without durable state; cases that reopen are then skipped.
   */
  reopen?(current: unknown): unknown;
  /** False when append refuses identities the store does not already hold. */
  digestAppend?: boolean;
  /**
   * The contract interfaces the backend implements; cases that need another
   * are skipped. Defaults to those of a full `CllBackend`; list `count` as
   * well for a backend that also implements `EntryCounter`.
   */
  interfaces?: readonly ConformanceInterface[];
}

export type ConformanceInterface =
  | "entries"
  | "checkpoint"
  | "witness"
  | "count"
  | "close";

export interface ConformanceCase {
  readonly name: string;
  /** Set when the backend lacks an interface or capability the case needs. */
  readonly skip?: string;
  run(): Promise<void>;
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Step = { op: string; expect: { result?: Json; error?: string } } & Record<
  string,
  Json
>;
interface Case {
  name: string;
  interfaces: string[];
  requires?: string[];
  unless?: string[];
  steps: Step[];
}

const operations: Record<string, readonly string[]> = {
  entries: ["append", "getEntry", "scanEntries"],
  checkpoint: ["loadCll", "commitCll"],
  witness: ["pendingWitnesses", "getWitness", "commitWitness"],
  count: ["entryCount"],
  close: ["close"],
};
const backendInterfaces = ["entries", "checkpoint", "witness", "close"];

/** Returns one runnable case per vector, skipped where it does not apply. */
export function conformanceCases(
  config: ConformanceConfig,
): readonly ConformanceCase[] {
  const capabilities = new Set<string>(["extended-years"]);
  if (config.digestAppend !== false) capabilities.add("digest-append");
  if (config.reopen !== undefined) capabilities.add("reopen");
  const implemented = new Set<string>(config.interfaces ?? backendInterfaces);
  return (vectors.cases as Case[]).map((item) => {
    const absent = item.interfaces.find((name) => !implemented.has(name));
    const missing = (item.requires ?? []).find((c) => !capabilities.has(c));
    const excluded = (item.unless ?? []).find((c) => capabilities.has(c));
    const skip =
      absent !== undefined
        ? `backend does not implement ${absent}`
        : missing !== undefined
          ? `backend lacks capability ${missing}`
          : excluded !== undefined
            ? `case applies only without capability ${excluded}`
            : undefined;
    return {
      name: item.name,
      ...(skip === undefined ? {} : { skip }),
      run: () => runCase(config, item),
    };
  });
}

async function runCase(config: ConformanceConfig, item: Case): Promise<void> {
  let subject = (await config.open()) as Record<string, unknown>;
  try {
    for (const name of item.interfaces)
      for (const op of operations[name] ?? [])
        if (typeof subject[op] !== "function")
          throw new Error(`${item.name}: backend does not implement ${op}`);
    for (const [index, step] of item.steps.entries()) {
      const label = `${item.name} step ${index} (${step.op})`;
      if (step.op === "reopen") {
        subject = (await config.reopen!(subject)) as Record<string, unknown>;
        continue;
      }
      let result: Json;
      try {
        result = await execute(subject, step);
      } catch (error) {
        const code = (error as Partial<CllError>).code;
        if (step.expect.error === undefined || code !== step.expect.error)
          throw new Error(
            `${label}: expected ${JSON.stringify(step.expect)}, got error ${String(code)}: ${(error as Error).message}`,
            { cause: error },
          );
        continue;
      }
      if (step.expect.error !== undefined)
        throw new Error(
          `${label}: expected error ${step.expect.error}, got ${JSON.stringify(result)}`,
        );
      const want = normalize(step.op, step.expect.result ?? null);
      const got = normalize(step.op, result);
      if (want !== got)
        throw new Error(`${label}: expected ${want}, got ${got}`);
    }
  } finally {
    if (typeof subject["close"] === "function")
      await (subject as { close(): Promise<void> }).close();
  }
}

async function execute(
  subject: Record<string, unknown>,
  step: Step,
): Promise<Json> {
  const entries = subject as unknown as EntryStore;
  const checkpoints = subject as unknown as CheckpointStateStore;
  const witnesses = subject as unknown as WitnessStateStore;
  switch (step.op) {
    case "append": {
      const input = step["input"] as { value: string; appendedAt: string };
      const result = await entries.append({
        value: bytes(input.value),
        appendedAt: new Date(input.appendedAt),
      });
      return {
        entry: { ...entryToWire(result.entry) },
        outcome: result.outcome,
      };
    }
    case "getEntry":
      return { ...entryToWire(await entries.getEntry(bytes(step["value"]))) };
    case "scanEntries":
      return (
        await entries.scanEntries(
          BigInt(step["afterSeq"] as string),
          step["limit"] as number,
        )
      ).map((entry) => ({ ...entryToWire(entry) }));
    case "entryCount":
      return String(await (subject as unknown as EntryCounter).entryCount());
    case "loadCll":
      return toJson(cllToWire(await checkpoints.loadCll()));
    case "commitCll":
      await checkpoints.commitCll(
        BigInt(step["expectedSize"] as string),
        step["expectedCheckpoint"] === undefined
          ? undefined
          : bytes(step["expectedCheckpoint"]),
        stateInput(step["next"] as Record<string, Json>),
      );
      return null;
    case "pendingWitnesses":
      return (
        await witnesses.pendingWitnesses(
          new Date(step["now"] as string),
          step["limit"] as number,
        )
      ).map((row) => toJson(witnessToWire(row)));
    case "getWitness": {
      const row = await witnesses.getWitness(
        step["witnessId"] as string,
        BigInt(step["checkpointSize"] as string),
      );
      // getWitness reports not found as undefined, which the contract
      // calls not_found.
      if (row === undefined)
        throw Object.assign(new Error("witness not found"), {
          code: "not_found",
        });
      return toJson(witnessToWire(row));
    }
    case "commitWitness":
      await witnesses.commitWitness(
        step["expectedAttempts"] as number,
        witnessInput(step["next"] as Record<string, Json>),
      );
      return null;
    case "close":
      await (subject as { close(): Promise<void> }).close();
      return null;
    default:
      throw new Error(`unknown conformance op ${step.op}`);
  }
}

const bytes = (value: Json | undefined): Uint8Array =>
  Uint8Array.from(Buffer.from(value as string, "base64"));

const toJson = (value: unknown): Json => JSON.parse(JSON.stringify(value));

/** Decodes a caller value without validating it, so the backend does. */
function witnessInput(wire: Record<string, Json>): WitnessState {
  const value: Record<string, unknown> = {
    ...wire,
    checkpointSize: BigInt(wire["checkpointSize"] as string),
    checkpoint: bytes(wire["checkpoint"]),
    nextAttemptAt: new Date(wire["nextAttemptAt"] as string),
  };
  if (wire["receipt"] !== undefined) value["receipt"] = bytes(wire["receipt"]);
  return value as unknown as WitnessState;
}

function stateInput(wire: Record<string, Json>): CllState {
  const value: Record<string, unknown> = {
    ...wire,
    size: BigInt(wire["size"] as string),
    indexedSeq: BigInt(wire["indexedSeq"] as string),
    nodes: (wire["nodes"] as string[]).map(bytes),
    witnesses: (wire["witnesses"] as Record<string, Json>[]).map(witnessInput),
  };
  if (wire["firstPendingAt"] !== undefined)
    value["firstPendingAt"] = new Date(wire["firstPendingAt"] as string);
  if (wire["checkpoint"] !== undefined)
    value["checkpoint"] = bytes(wire["checkpoint"]);
  for (const key of ["checkpointSize", "checkpointIndexedSeq"])
    if (wire[key] !== undefined) value[key] = BigInt(wire[key] as string);
  if (wire["checkpointPeaks"] !== undefined)
    value["checkpointPeaks"] = (wire["checkpointPeaks"] as string[]).map(bytes);
  return value as unknown as CllState;
}

/** Canonical JSON text; loadCll witness order is not part of the contract. */
function normalize(op: string, value: Json): string {
  if (op === "loadCll" && value !== null && typeof value === "object") {
    const state = value as Record<string, Json>;
    const rows = [...(state["witnesses"] as Record<string, Json>[])];
    rows.sort((a, b) => {
      const left = BigInt(a["checkpointSize"] as string);
      const right = BigInt(b["checkpointSize"] as string);
      if (left !== right) return left < right ? -1 : 1;
      return Buffer.compare(
        Buffer.from(a["witnessId"] as string),
        Buffer.from(b["witnessId"] as string),
      );
    });
    value = { ...state, witnesses: rows };
  }
  return canonical(value);
}

function canonical(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key]!)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
