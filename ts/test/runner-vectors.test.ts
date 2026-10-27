import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CheckpointRunner,
  CllError,
  MemoryStore,
  WitnessDeliveryRunner,
  createCheckpointIdentity,
  limits,
  type CllState,
  type WitnessClient,
  type WitnessReceipt,
} from "../src/index.js";
import { cllToWire } from "../src/serde.js";

// Byte-for-byte copy of runner-conformance-vectors/vectors.json, which the Go
// runners generate; `go run ./test/runnervectors -check` keeps it identical.
// Replaying it proves the TypeScript runners leave the same durable state,
// with byte-identical checkpoint statements, as Go on the same steps.
type Outcome = {
  receipt?: {
    bytes: string;
    entryHash: string;
    entryHashScheme: "legacy";
    leafIndex: number;
    treeSize: number;
  };
  error?: "retryable" | "permanent";
};
type Step = {
  op: string;
  value?: string;
  appendedAt?: string;
  now?: string;
  limit?: number;
  submit?: Record<string, Outcome[]>;
  verify?: Record<string, boolean[]>;
  expect?: { result: unknown };
};
type Case = {
  name: string;
  requires?: string[];
  config: {
    cadenceEntries: number;
    cadenceAgeMs: number;
    scanLimit: number;
    witnessIds: string[] | null;
    baseBackoffMs: number;
    maxBackoffMs: number;
  };
  steps: Step[];
};
const vectors = JSON.parse(
  readFileSync(resolve("test/testdata/runner-vectors.json"), "utf8"),
) as {
  version: number;
  signingKeySeed: string;
  logId: string;
  capabilities: Record<string, string>;
  cases: Case[];
};

// The TypeScript checkpoint runner catches up on the whole backlog in one
// pass, and its delivery runner keeps delivering a witness's later rows after
// a retryable failure, so it lacks these two capabilities.
const capabilities = new Set<string>();

const normalize = (state: CllState): unknown => {
  const wire = cllToWire(state);
  const witnesses = [...wire.witnesses]
    .sort(
      (a, b) =>
        Number(BigInt(a.checkpointSize) - BigInt(b.checkpointSize)) ||
        (a.witnessId < b.witnessId ? -1 : a.witnessId > b.witnessId ? 1 : 0),
    )
    .map((row) =>
      row.lastError === undefined ? row : { ...row, lastError: "<set>" },
    );
  return JSON.parse(JSON.stringify({ ...wire, witnesses }));
};

async function replay(item: Case): Promise<void> {
  const store = new MemoryStore();
  let now = new Date(0);
  const witnessIds = item.config.witnessIds ?? [];
  const runner = new CheckpointRunner(store, {
    logId: vectors.logId,
    identity: createCheckpointIdentity(
      Buffer.from(vectors.signingKeySeed, "hex"),
    ),
    witnessIds,
    entryCadence: item.config.cadenceEntries,
    ageCadenceMs: item.config.cadenceAgeMs,
    scanLimit: item.config.scanLimit,
    clock: () => now,
  });
  let submit = new Map<string, Outcome[]>();
  let verify = new Map<string, boolean[]>();
  const clients = new Map<string, WitnessClient>(
    witnessIds.map((id) => [
      id,
      {
        id,
        async submit(): Promise<WitnessReceipt> {
          const outcome = submit.get(id)?.shift();
          if (outcome === undefined)
            throw new Error(`witness ${id} submitted more than scripted`);
          if (outcome.error === "retryable")
            throw new CllError("contention", "scripted retryable failure");
          if (outcome.error === "permanent")
            throw new CllError("rejected", "scripted permanent failure");
          const receipt = outcome.receipt!;
          return { ...receipt, bytes: Buffer.from(receipt.bytes, "base64") };
        },
      },
    ]),
  );
  const delivery = new WitnessDeliveryRunner(store, clients, {
    verifiers: new Map(
      witnessIds.map((id) => [
        id,
        {
          verify: () => {
            const answer = verify.get(id)?.shift();
            if (answer === undefined)
              throw new Error(`witness ${id} verified more than scripted`);
            return answer;
          },
        },
      ]),
    ),
    now: () => now,
    baseBackoffMs: item.config.baseBackoffMs,
    maxBackoffMs: item.config.maxBackoffMs,
    jitter: false,
  });
  for (const [index, step] of item.steps.entries()) {
    const label = `${item.name} step ${index} (${step.op})`;
    switch (step.op) {
      case "append":
        await store.append({
          value: Buffer.from(step.value!, "base64"),
          appendedAt: new Date(step.appendedAt!),
        });
        break;
      case "runCheckpoint":
        now = new Date(step.now!);
        await runner.runOnce();
        break;
      case "deliverWitnesses": {
        now = new Date(step.now!);
        submit = new Map(
          Object.entries(step.submit ?? {}).map(([id, list]) => [
            id,
            [...list],
          ]),
        );
        verify = new Map(
          Object.entries(step.verify ?? {}).map(([id, list]) => [
            id,
            [...list],
          ]),
        );
        // runOnce's limit parameter is typed by its default, limits.witnesses.
        const completed = await delivery.runOnce(
          step.limit as typeof limits.witnesses,
        );
        expect(
          [...submit.values(), ...verify.values()].every((x) => x.length === 0),
          `${label}: scripted answers left unused`,
        ).toBe(true);
        expect(completed, label).toBe(step.expect!.result);
        break;
      }
      case "loadCll":
        expect(normalize(await store.loadCll()), label).toEqual(
          step.expect!.result,
        );
        break;
      default:
        throw new Error(`${label}: unknown op`);
    }
  }
}

describe("runner conformance vectors", () => {
  it("names only known capabilities", () => {
    expect(vectors.version).toBe(1);
    expect(Object.keys(vectors.capabilities).sort()).toEqual([
      "bounded-run",
      "stop-after-retryable",
    ]);
  });
  for (const item of vectors.cases) {
    const missing = (item.requires ?? []).find((c) => !capabilities.has(c));
    it.skipIf(missing !== undefined)(item.name, () => replay(item));
  }
  it("skips exactly the cases that need a missing capability", () => {
    expect(
      vectors.cases
        .filter((item) => (item.requires ?? []).length > 0)
        .map((item) => item.name),
    ).toEqual(["checkpoint/bounded-batches", "witness/stop-after-retryable"]);
  });
});
