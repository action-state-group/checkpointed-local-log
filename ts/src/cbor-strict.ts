// A CBOR decoder for witness receipts, adapted from
// action-state-group/agent-action-capsule ts/src/cose-receipt.ts at
// go/v0.18.0 (BSD-3-Clause, Copyright (c) 2026 Action State Group, Inc.),
// so the two receipt verifiers decode the same
// bytes the same way (checkpoint-conformance-vectors/receipt-vectors.json).

const MAX_DEPTH = 32;

/** A decoded CBOR item. Integers are bigints, floats are numbers. */
export type CborValue =
  | bigint
  | number
  | boolean
  | null
  | undefined
  | string
  | Uint8Array
  | readonly CborValue[]
  | CborMap
  | CborTag
  | CborSimple;
export class CborMap {
  public constructor(
    public readonly entries: readonly (readonly [CborValue, CborValue])[],
  ) {}
  public has(key: bigint | string): boolean {
    return this.entries.some(([k]) => k === key);
  }
  public get(key: bigint | string): CborValue {
    return this.entries.find(([k]) => k === key)?.[1];
  }
}
export class CborTag {
  public constructor(
    public readonly tag: bigint,
    public readonly value: CborValue,
  ) {}
}
export class CborSimple {
  public constructor(public readonly value: number) {}
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decode one CBOR item under the deterministic-encoding rules scitt-cose's
 * `strict_decode` applies: definite lengths, the shortest form of every
 * argument and float, no repeated map key and no trailing bytes. Map order is
 * not checked.
 */
export function decodeStrictCbor(data: Uint8Array): CborValue {
  return decodeCbor(data, true);
}

/**
 * Decode one CBOR item as the scitt-cose verifiers decode an inclusion-proof
 * blob: a non-shortest argument or float and indefinite-length strings,
 * arrays and maps are accepted. Unique map keys and no trailing bytes still
 * hold.
 */
export function decodeLenientCbor(data: Uint8Array): CborValue {
  return decodeCbor(data, false);
}

function decodeCbor(data: Uint8Array, shortest: boolean): CborValue {
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
    if (shortest && value < [24n, 1n << 8n, 1n << 16n, 1n << 32n][add - 24]!)
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
      if (add === 23) return undefined;
      if (add < 20) return new CborSimple(add);
      if (add === 24) {
        const value = byte();
        if (value < 32) throw new SyntaxError("non-preferred simple value");
        return new CborSimple(value);
      }
      if (add >= 28) throw new SyntaxError("reserved or break CBOR value");
      const raw = take(add === 25 ? 2n : add === 26 ? 4n : 8n);
      const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      if (add === 25) return halfFloat(view.getUint16(0));
      const value = add === 26 ? view.getFloat32(0) : view.getFloat64(0);
      if (
        shortest &&
        (Number.isNaN(value) ||
          fitsHalf(value) ||
          (add === 27 && Math.fround(value) === value))
      )
        throw new SyntaxError("CBOR float is not in its shortest form");
      return value;
    }
    if (!shortest && add === 31 && major >= 2 && major <= 5) {
      const atBreak = (): boolean => {
        if (data[offset] !== 0xff) return false;
        offset += 1;
        return true;
      };
      if (major === 2 || major === 3) {
        // Each chunk is a definite-length string of the same major type.
        const chunks: Uint8Array[] = [];
        while (!atBreak()) {
          const head = byte();
          if (head >>> 5 !== major || (head & 31) === 31)
            throw new SyntaxError("invalid indefinite-length string chunk");
          chunks.push(take(argument(head & 31)));
        }
        const joined = new Uint8Array(
          chunks.reduce((sum, chunk) => sum + chunk.length, 0),
        );
        let at = 0;
        for (const chunk of chunks) {
          if (major === 3) utf8.decode(chunk); // each chunk is valid UTF-8
          joined.set(chunk, at);
          at += chunk.length;
        }
        return major === 2 ? joined : utf8.decode(joined);
      }
      if (major === 4) {
        const out: CborValue[] = [];
        while (!atBreak()) out.push(item(depth + 1));
        return out;
      }
      const entries: [CborValue, CborValue][] = [],
        keys = new Set<string>();
      while (!atBreak()) {
        const key = item(depth + 1),
          identity = identityOf(key);
        if (keys.has(identity)) throw new SyntaxError("duplicate CBOR map key");
        keys.add(identity);
        entries.push([key, item(depth + 1)]);
      }
      return new CborMap(entries);
    }
    const length = argument(add);
    if (major === 0) return length;
    if (major === 1) return -1n - length;
    if (major === 2) return take(length);
    if (major === 3) return utf8.decode(take(length));
    if (major === 6) return new CborTag(length, item(depth + 1));
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
      const key = item(depth + 1),
        identity = identityOf(key);
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

/**
 * A decoded CBOR integer, a bignum (tag 2 or 3) included, as the scitt-cose
 * verifiers read the integers of an inclusion proof.
 */
export function cborInteger(value: CborValue): bigint | undefined {
  if (typeof value === "bigint") return value;
  if (
    value instanceof CborTag &&
    (value.tag === 2n || value.tag === 3n) &&
    value.value instanceof Uint8Array
  ) {
    let magnitude = 0n;
    for (const octet of value.value)
      magnitude = (magnitude << 8n) | BigInt(octet);
    return value.tag === 2n ? magnitude : -1n - magnitude;
  }
  return undefined;
}

function halfFloat(bits: number): number {
  const exponent = (bits >>> 10) & 0x1f,
    fraction = bits & 0x3ff,
    sign = bits & 0x8000 ? -1 : 1;
  if (exponent === 0) return sign * fraction * 2 ** -24;
  if (exponent === 31) return fraction ? Number.NaN : sign * Infinity;
  return sign * (1 + fraction / 1024) * 2 ** (exponent - 15);
}

/** Whether a float is exactly representable in IEEE 754 half precision. */
function fitsHalf(value: number): boolean {
  const magnitude = Math.abs(value);
  if (magnitude === 0 || magnitude === Infinity) return true;
  if (magnitude > 65504) return false;
  const exponent = Math.floor(Math.log2(magnitude));
  return Number.isInteger(
    magnitude * 2 ** (exponent >= -14 ? 10 - exponent : 24),
  );
}

function identityOf(value: CborValue): string {
  if (typeof value === "bigint") return `i${value}`;
  if (typeof value === "number") return `f${value}`;
  if (typeof value === "string") return `t${JSON.stringify(value)}`;
  if (value instanceof Uint8Array) return `b${value.join()}`;
  if (Array.isArray(value)) return `a[${value.map(identityOf).join(",")}]`;
  if (value instanceof CborMap)
    return `m{${value.entries
      .map(([k, v]) => `${identityOf(k)}:${identityOf(v)}`)
      .sort()
      .join(",")}}`;
  if (value instanceof CborTag)
    return `g${value.tag}(${identityOf(value.value)})`;
  if (value instanceof CborSimple) return `s${value.value}`;
  return `s${String(value)}`;
}
