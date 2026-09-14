import { createHash } from "node:crypto";
import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [mode, backendName, target, logId, argument, secondArgument] =
  process.argv.slice(2);
if (
  mode === undefined ||
  backendName === undefined ||
  target === undefined ||
  logId === undefined
)
  throw new Error(
    "usage: storage.mjs <advance|verify|hold|expect-contention> <jsonl|sqlite|mysql> <target> <log-id> [argument]",
  );

const dist = process.env.CLL_TS_DIST;
if (dist === undefined) throw new Error("CLL_TS_DIST is required");

const core = await import(pathToFileURL(join(dist, "index.js")).href);
const backendModule = await import(
  pathToFileURL(join(dist, `${backendName}.js`)).href
);
const baseTime = new Date("2026-09-03T12:00:00.123Z");
const witnessId = "interop-witness";

const openBackend = async () => {
  switch (backendName) {
    case "jsonl":
      return backendModule.JsonlStore.open(target);
    case "sqlite":
      return backendModule.SqliteStore.open(target, logId);
    case "mysql":
      return backendModule.MysqlStore.open(target, logId);
    default:
      throw new Error(`unsupported backend ${backendName}`);
  }
};

if (mode === "expect-contention") {
  try {
    const store = await openBackend();
    await store.close();
    throw new Error("second writer unexpectedly opened");
  } catch (error) {
    if (error?.code !== "contention") throw error;
  }
} else {
  const store = await openBackend();
  let failure;
  try {
    switch (mode) {
      case "advance":
        await advance(store);
        break;
      case "verify": {
        const expected = Number(argument);
        if (!Number.isSafeInteger(expected) || expected < 0)
          throw new Error("verify requires expected entry count");
        await verify(store, expected);
        break;
      }
      case "hold":
        if (argument === undefined || secondArgument === undefined)
          throw new Error("hold requires ready and stop paths");
        await hold(argument, secondArgument);
        break;
      default:
        throw new Error(`unsupported mode ${mode}`);
    }
  } catch (error) {
    failure = error;
  }
  try {
    await store.close();
  } catch (error) {
    failure =
      failure === undefined
        ? error
        : new AggregateError([failure, error], "operation and close failed");
  }
  if (failure !== undefined) throw failure;
}

async function advance(store) {
  const entries = await store.scanEntries(0n, 1000);
  await verify(store, entries.length);
  const sequence = entries.length + 1;
  if (sequence > 255) throw new Error("interop sequence exceeds fixture range");

  const identity = identityFor(sequence);
  const result = await store.append({
    value: identity,
    appendedAt: timeFor(sequence),
  });
  if (result.outcome !== "inserted" || result.entry.seq !== BigInt(sequence))
    throw new Error("unexpected append result");

  const state = await store.loadCll();
  const tree = new core.MmrTree(state.nodes);
  tree.append(identity);
  const checkpoint = checkpointFor(sequence);
  const previousSize = state.checkpointSize;
  const next = {
    ...state,
    size: tree.size,
    nodes: tree.nodes(),
    indexedSeq: BigInt(sequence),
    checkpoint,
    checkpointSize: tree.size,
    checkpointIndexedSeq: BigInt(sequence),
    checkpointPeaks: tree.peakHashes(),
    witnesses: [
      ...state.witnesses,
      {
        witnessId,
        checkpointSize: tree.size,
        checkpoint,
        attempts: 0,
        nextAttemptAt: timeFor(sequence),
        permanent: false,
      },
    ],
  };
  await store.commitCll(state.size, state.checkpoint, next);
  if (previousSize !== undefined)
    await completeWitness(store, previousSize, sequence - 1, sequence);
  await verify(store, sequence);
}

async function completeWitness(
  store,
  checkpointSize,
  checkpointSequence,
  currentSequence,
) {
  const current = await store.getWitness(witnessId, checkpointSize);
  if (current === undefined) throw new Error("previous witness is missing");
  const digest = createHash("sha256").update(current.checkpoint).digest("hex");
  await store.commitWitness(current.attempts, {
    ...current,
    attempts: current.attempts + 1,
    nextAttemptAt: timeFor(currentSequence),
    receipt: receiptFor(checkpointSequence),
    entryHash: digest,
    entryHashScheme: "legacy",
    leafIndex: checkpointSequence - 1,
    treeSize: currentSequence,
    permanent: false,
  });
}

async function verify(store, expected) {
  const entries = await store.scanEntries(0n, 1000);
  if (entries.length !== expected)
    throw new Error(`got ${entries.length} entries, want ${expected}`);

  const tree = new core.MmrTree();
  const sizes = [];
  for (const [index, entry] of entries.entries()) {
    const sequence = index + 1;
    if (
      entry.seq !== BigInt(sequence) ||
      !same(entry.value, identityFor(sequence)) ||
      entry.appendedAt.toISOString() !== timeFor(sequence).toISOString()
    )
      throw new Error(`entry ${sequence} disagrees with portable fixture`);
    tree.append(entry.value);
    sizes.push(tree.size);
  }

  const state = await store.loadCll();
  if (
    state.size !== tree.size ||
    state.indexedSeq !== BigInt(expected) ||
    !sameList(state.nodes, tree.nodes()) ||
    state.witnesses.length !== expected ||
    state.firstPendingAt !== undefined
  )
    throw new Error("CLL state disagrees with portable fixture");
  if (expected === 0) {
    if (state.checkpoint !== undefined)
      throw new Error("empty fixture has a checkpoint");
    return;
  }
  if (
    state.checkpoint === undefined ||
    state.checkpointSize !== tree.size ||
    state.checkpointIndexedSeq !== BigInt(expected) ||
    !same(state.checkpoint, checkpointFor(expected)) ||
    !sameList(state.checkpointPeaks, tree.peakHashes())
  )
    throw new Error("latest checkpoint disagrees with portable fixture");

  for (const [index, size] of sizes.entries()) {
    const sequence = index + 1;
    const item = await store.getWitness(witnessId, size);
    if (item === undefined || !same(item.checkpoint, checkpointFor(sequence)))
      throw new Error(`witness ${sequence} checkpoint mismatch`);
    if (sequence === expected) {
      if (item.attempts !== 0 || item.receipt !== undefined)
        throw new Error("latest witness is not pending");
    } else {
      verifyReceipt(item, sequence);
    }
  }
  const pending = await store.pendingWitnesses(
    new Date(baseTime.valueOf() + 24 * 60 * 60 * 1000),
    32,
  );
  if (pending.length !== 1 || pending[0].checkpointSize !== sizes.at(-1))
    throw new Error("pending witness projection mismatch");
}

function verifyReceipt(item, sequence) {
  const digest = createHash("sha256")
    .update(checkpointFor(sequence))
    .digest("hex");
  if (
    item.attempts !== 1 ||
    item.receipt === undefined ||
    !same(item.receipt, receiptFor(sequence)) ||
    item.entryHash !== digest ||
    item.entryHashScheme !== "legacy" ||
    item.leafIndex !== sequence - 1 ||
    item.treeSize !== sequence + 1
  )
    throw new Error(`witness ${sequence} receipt mismatch`);
}

function identityFor(sequence) {
  return Uint8Array.from({ length: 32 }, () => sequence);
}

function checkpointFor(sequence) {
  return Uint8Array.of(0xc0, sequence);
}

function receiptFor(sequence) {
  return Uint8Array.of(0xd0, sequence);
}

function timeFor(sequence) {
  return new Date(baseTime.valueOf() + sequence * 1000);
}

function same(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function sameList(left, right) {
  return (
    left !== undefined &&
    right !== undefined &&
    left.length === right.length &&
    left.every((value, index) => same(value, right[index]))
  );
}

async function hold(readyPath, stopPath) {
  await writeFile(readyPath, "ready\n", { mode: 0o600 });
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      await access(stopPath);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out waiting for stop file");
}
