// A CBOR decoder for witness receipts under the receipt encoding rule of
// action-state-group/agent-action-capsule ts/src/cose-receipt.ts
// (decodeReceiptItem) at c4b83db74b311af1c2c816f8866a940bff4f2347,
// agent-action-capsule#523 (BSD-3-Clause, Copyright (c) 2026 Action State
// Group, Inc.), so the two receipt verifiers decode the same bytes the same
// way (checkpoint-conformance-vectors/receipt-vectors.json).

/** The deepest nesting the receipt encoding rule allows. */
const MAX_DEPTH = 16;
const COSE_SIGN1_TAG = 18n;
const INT64_MIN = -(1n << 63n);

/** A decoded CBOR item under the receipt encoding rule. */
export type CborValue =
  | bigint
  | boolean
  | null
  | string
  | Uint8Array
  | readonly CborValue[]
  | CborMap
  | CborTag;
export class CborMap {
  public constructor(
    public readonly entries: readonly (readonly [CborValue, CborValue])[],
  ) {}
  public has(key: bigint | string): boolean {
    return this.entries.some(([k]) => k === key);
  }
  public get(key: bigint | string): CborValue | undefined {
    return this.entries.find(([k]) => k === key)?.[1];
  }
}
export class CborTag {
  public constructor(
    public readonly tag: bigint,
    public readonly value: CborValue,
  ) {}
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decode one CBOR item under the receipt encoding rule of
 * agent-action-capsule's interop profile v1 section 6.2.2: no trailing bytes,
 * definite lengths, the shortest form of every argument, no repeated map key,
 * integers from -2^63 to 2^64 - 1, integer or text map keys, valid UTF-8, no
 * float, no simple value but false, true and null, no tag but an outer 18
 * when `topTag`, and at most 16 levels. Map order is not checked. Throws
 * otherwise.
 */
export function decodeReceiptItem(
  data: Uint8Array,
  topTag: boolean,
): CborValue {
  let offset = 0;
  const byte = (): number => {
    const value = data[offset++];
    if (value === undefined) throw new SyntaxError("truncated CBOR");
    return value;
  };
  const take = (length: bigint): Uint8Array => {
    if (BigInt(offset) + length > BigInt(data.length))
      throw new SyntaxError("truncated CBOR");
    const value = data.slice(offset, offset + Number(length));
    offset += Number(length);
    return value;
  };
  const argument = (add: number): bigint => {
    if (add < 24) return BigInt(add);
    const width = [1, 2, 4, 8][add - 24];
    if (width === undefined)
      throw new SyntaxError("indefinite or reserved CBOR length");
    let value = 0n;
    for (let i = 0; i < width; i += 1) value = (value << 8n) | BigInt(byte());
    if (value < [24n, 1n << 8n, 1n << 16n, 1n << 32n][add - 24]!)
      throw new SyntaxError("CBOR argument is not in its shortest form");
    return value;
  };
  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new SyntaxError("CBOR nesting too deep");
    const first = byte(),
      major = first >>> 5,
      add = first & 31;
    if (major === 7) {
      if (add === 20) return false;
      if (add === 21) return true;
      if (add === 22) return null;
      throw new SyntaxError("a float or a simple value");
    }
    const length = argument(add);
    if (major === 0) return length;
    if (major === 1) {
      if (-1n - length < INT64_MIN)
        throw new SyntaxError("an integer below -2^63");
      return -1n - length;
    }
    if (major === 2) return take(length);
    if (major === 3) return utf8.decode(take(length));
    if (major === 6) {
      if (!(depth === 0 && topTag && length === COSE_SIGN1_TAG))
        throw new SyntaxError("a tag other than the outer tag 18");
      return new CborTag(length, item(depth + 1));
    }
    // Every element takes at least one byte: refuse a count the rest of the
    // input cannot hold before looping over it.
    if (length > BigInt(data.length - offset))
      throw new SyntaxError("truncated CBOR");
    if (major === 4) {
      const out: CborValue[] = [];
      for (let i = 0n; i < length; i += 1n) out.push(item(depth + 1));
      return out;
    }
    const entries: [CborValue, CborValue][] = [],
      keys = new Set<string>();
    for (let i = 0n; i < length; i += 1n) {
      const key = item(depth + 1);
      if (typeof key !== "bigint" && typeof key !== "string")
        throw new SyntaxError("a map key that is not an integer or text");
      const identity =
        typeof key === "bigint" ? `i${key}` : `t${JSON.stringify(key)}`;
      if (keys.has(identity)) throw new SyntaxError("duplicate CBOR map key");
      keys.add(identity);
      entries.push([key, item(depth + 1)]);
    }
    return new CborMap(entries);
  };
  const value = item(0);
  if (offset !== data.length) throw new SyntaxError("trailing CBOR bytes");
  return value;
}
