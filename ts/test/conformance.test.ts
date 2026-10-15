import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { conformanceCases } from "../src/conformance.js";
import { MemoryStore } from "../src/index.js";
import { JsonlStore } from "../src/jsonl.js";
import { SqliteStore } from "../src/sqlite.js";

it("pins the repository conformance vectors", () => {
  expect(readFileSync(resolve("src/conformance/vectors.json"), "utf8")).toBe(
    readFileSync(
      resolve("../backend-conformance-vectors/vectors.json"),
      "utf8",
    ),
  );
});

const temp = (name: string) =>
  join(mkdtempSync(join(tmpdir(), `cll-conformance-${name}-`)), name);

describe("conformance vectors: Memory", () => {
  for (const item of conformanceCases({ open: () => new MemoryStore() }))
    it.skipIf(item.skip !== undefined)(item.name, item.run);
});

describe("conformance vectors: JSONL", () => {
  const paths = new WeakMap<object, string>();
  for (const item of conformanceCases({
    open: async () => {
      const path = temp("cll.jsonl");
      const store = await JsonlStore.open(path);
      paths.set(store, path);
      return store;
    },
    reopen: async (current) => {
      const path = paths.get(current as object)!;
      await (current as JsonlStore).close();
      const store = await JsonlStore.open(path);
      paths.set(store, path);
      return store;
    },
  }))
    it.skipIf(item.skip !== undefined)(item.name, item.run);
});

describe("conformance vectors: SQLite", () => {
  const paths = new WeakMap<object, string>();
  for (const item of conformanceCases({
    open: () => {
      const path = temp("cll.sqlite");
      const store = SqliteStore.open(path, "conformance");
      paths.set(store, path);
      return store;
    },
    reopen: async (current) => {
      const path = paths.get(current as object)!;
      await (current as SqliteStore).close();
      const store = SqliteStore.open(path, "conformance");
      paths.set(store, path);
      return store;
    },
  }))
    it.skipIf(item.skip !== undefined)(item.name, item.run);
});

describe("conformance vectors: EntryStore subset", () => {
  for (const item of conformanceCases({
    interfaces: ["entries"],
    open: () => {
      const store = new MemoryStore();
      return {
        append: store.append.bind(store),
        getEntry: store.getEntry.bind(store),
        scanEntries: store.scanEntries.bind(store),
      };
    },
  }))
    it.skipIf(item.skip !== undefined)(item.name, item.run);
});

it("skips exactly the cases a subset backend cannot run", () => {
  const cases = conformanceCases({
    interfaces: ["entries"],
    open: () => new MemoryStore(),
  });
  const runnable = cases.filter((item) => item.skip === undefined);
  expect(runnable.length).toBeGreaterThan(0);
  expect(runnable.every((item) => item.name.startsWith("entries/"))).toBe(true);
  expect(
    conformanceCases({ open: () => new MemoryStore() }).filter((item) =>
      item.skip?.startsWith("backend does not implement"),
    ),
  ).toEqual([]);
});
