// Cases shared by the Node test (test/browser-checkpoint.test.ts) and the
// headless Chrome test (test/browser/checkpoint.browser.test.ts) of the
// browser entry's checkpoint verifier. Plain data and pure functions only, so
// it loads in both environments.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { encode, rfc8949EncodeOptions } from "cborg";

const { Point } = ed25519;
const L = Point.Fn.ORDER;

export const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../gu) ?? [], (byte) => parseInt(byte, 16));
export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

export interface CoseVectors {
  readonly cases: readonly {
    readonly name: string;
    readonly claims_hex: string;
    readonly cose_hex: string;
  }[];
}
export interface CheckpointVectors {
  readonly cases: readonly {
    readonly name: string;
    readonly log_id: string;
    readonly mmr_size: number;
    readonly root: string;
    readonly prev_size: number;
    readonly prev_root: string;
    readonly key_id: string;
    readonly timestamp: string;
  }[];
}

/** The metadata each COSE vector must yield, from the vectors.json case. */
export const expectedMetadata = (
  coseVectors: CoseVectors,
  checkpointVectors: CheckpointVectors,
) =>
  coseVectors.cases.map((cose) => {
    const legacy = checkpointVectors.cases.find(
      (candidate) => candidate.name === cose.name,
    );
    if (legacy === undefined) throw new Error(`no vector for ${cose.name}`);
    return {
      name: cose.name,
      cose: fromHex(cose.cose_hex),
      metadata: {
        logId: legacy.log_id,
        size: BigInt(legacy.mmr_size),
        previousSize: BigInt(legacy.prev_size),
        root: legacy.root,
        previousRoot: legacy.prev_root,
        keyId: legacy.key_id,
        timestamp: legacy.timestamp,
      },
    };
  });

/** One-bit changes across the whole statement, each a statement to refuse. */
export const mutations = (cose: Uint8Array): Uint8Array[] =>
  Array.from({ length: cose.length * 2 }, (_, i) => {
    const mutated = Uint8Array.from(cose);
    mutated[i >> 1] = mutated[i >> 1]! ^ (i & 1 ? 0x80 : 0x01);
    return mutated;
  });

const littleEndian = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1)
    value = (value << 8n) | BigInt(bytes[i]!);
  return value;
};
const scalarBytes = (value: bigint): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, i) =>
    Number((value >> BigInt(8 * i)) & 0xffn),
  );
const challenge = (r: Uint8Array, a: Uint8Array, m: Uint8Array): bigint => {
  const input = new Uint8Array(64 + m.length);
  input.set(r);
  input.set(a, 32);
  input.set(m, 64);
  return littleEndian(sha512(input)) % L;
};

export const smallOrderEncodings = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

export interface Ed25519Case {
  readonly name: string;
  readonly publicKey: Uint8Array;
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
  /** True only for an honest signature; every other case must be refused. */
  readonly valid: boolean;
}

/**
 * Ed25519 inputs where implementations are known to disagree, plus an honest
 * signature and one-bit changes to it. Deterministic.
 */
export function ed25519Cases(): Ed25519Case[] {
  const secret = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const { scalar, pointBytes: publicKey } =
    ed25519.utils.getExtendedPublicKey(secret);
  const message = new TextEncoder().encode("cll browser verifier edge cases");
  const signature = ed25519.sign(message, secret);
  const cases: Ed25519Case[] = [
    { name: "honest", publicKey, message, signature, valid: true },
  ];
  const s = littleEndian(signature.subarray(32));
  const highS = Uint8Array.from(signature);
  highS.set(scalarBytes(s + L), 32);
  cases.push({
    name: "S + L",
    publicKey,
    message,
    signature: highS,
    valid: false,
  });

  // R with a small-order component: passes the cofactored equation (noble's
  // `verify`), fails the cofactorless one (OpenSSL, WebCrypto).
  const torsion = Point.fromHex(smallOrderEncodings[4]!, false);
  const nonce = 0x1234567n;
  const mixedR = Point.BASE.multiply(nonce).add(torsion).toBytes();
  const mixedS = (nonce + challenge(mixedR, publicKey, message) * scalar) % L;
  const mixed = new Uint8Array(64);
  mixed.set(mixedR);
  mixed.set(scalarBytes(mixedS), 32);
  cases.push({
    name: "mixed-order R",
    publicKey,
    message,
    signature: mixed,
    valid: false,
  });

  // R the identity, a small-order point, with S = k * a: the cofactorless
  // equation holds, so only the small-order check refuses it.
  const identityR = fromHex(smallOrderEncodings[0]!);
  const identityS = (challenge(identityR, publicKey, message) * scalar) % L;
  const identitySignature = new Uint8Array(64);
  identitySignature.set(identityR);
  identitySignature.set(scalarBytes(identityS), 32);
  cases.push({
    name: "identity R",
    publicKey,
    message,
    signature: identitySignature,
    valid: false,
  });

  // Small-order public keys, each with a signature R = rB, S = r over a
  // message whose challenge k is a multiple of 8, so [k]A is the identity and
  // the cofactorless equation holds.
  for (const encoding of smallOrderEncodings) {
    const a = fromHex(encoding);
    const r = Point.BASE.multiply(nonce).toBytes();
    let counter = 0;
    let smallOrderMessage: Uint8Array;
    do {
      smallOrderMessage = new TextEncoder().encode(`small order ${counter}`);
      counter += 1;
    } while (challenge(r, a, smallOrderMessage) % 8n !== 0n);
    const smallOrderSignature = new Uint8Array(64);
    smallOrderSignature.set(r);
    smallOrderSignature.set(scalarBytes(nonce), 32);
    cases.push({
      name: `small-order A ${encoding.slice(0, 8)}`,
      publicKey: a,
      message: smallOrderMessage,
      signature: smallOrderSignature,
      valid: false,
    });
  }

  // Non-canonical encodings of y (p <= y < 2^255) as A and as R.
  for (let i = 0; i < 19; i += 1) {
    const nonCanonical = fromHex(
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    );
    nonCanonical[0] = 0xed + i;
    cases.push({
      name: `non-canonical A y=p+${i}`,
      publicKey: nonCanonical,
      message,
      signature,
      valid: false,
    });
    const nonCanonicalR = Uint8Array.from(signature);
    nonCanonicalR.set(nonCanonical);
    cases.push({
      name: `non-canonical R y=p+${i}`,
      publicKey,
      message,
      signature: nonCanonicalR,
      valid: false,
    });
  }

  for (let bit = 0; bit < 512; bit += 7) {
    const flipped = Uint8Array.from(signature);
    flipped[bit >> 3] = flipped[bit >> 3]! ^ (1 << (bit & 7));
    cases.push({
      name: `signature bit ${bit}`,
      publicKey,
      message,
      signature: flipped,
      valid: false,
    });
  }
  for (let bit = 0; bit < 256; bit += 5) {
    const flipped = Uint8Array.from(publicKey);
    flipped[bit >> 3] = flipped[bit >> 3]! ^ (1 << (bit & 7));
    cases.push({
      name: `key bit ${bit}`,
      publicKey: flipped,
      message,
      signature,
      valid: false,
    });
  }
  return cases;
}

const canonical = (value: unknown): Uint8Array =>
  encode(value, rfc8949EncodeOptions);

/**
 * A well-formed one-leaf checkpoint statement whose key is the identity
 * point, a small-order key. Its signature needs no private key: R = rB and
 * S = r satisfy [S]B = R + [k]A whenever [k]A is the identity, so the
 * timestamp is chosen to make k a multiple of 8. Chrome's WebCrypto Ed25519
 * accepts it; the Node entry refuses it, so the browser entry must too.
 */
export function smallOrderKeyStatement(): Uint8Array {
  const kid = fromHex(smallOrderEncodings[0]!);
  const nonce = 0x1234567n;
  const r = Point.BASE.multiply(nonce).toBytes();
  for (let second = 0; ; second += 1) {
    const logId = "forged-log";
    const protectedBytes = canonical(
      new Map<unknown, unknown>([
        [1, -8],
        [3, "application/cll-checkpoint+cbor"],
        [4, kid],
        [
          15,
          new Map([
            [1, logId],
            [2, `${logId}#1`],
          ]),
        ],
      ]),
    );
    const payload = canonical({
      kind: "cll-checkpoint",
      log_size: 1,
      commitment: canonical([new Uint8Array(32).fill(0x42)]),
      prev_size: 0,
      prev_commitment: new Uint8Array(),
      issued_at: `2026-10-27T00:${String(Math.floor(second / 60) % 60).padStart(2, "0")}:${String(second % 60).padStart(2, "0")}Z`,
    });
    const message = canonical([
      "Signature1",
      protectedBytes,
      new Uint8Array(),
      payload,
    ]);
    if (challenge(r, kid, message) % 8n !== 0n) continue;
    const signature = new Uint8Array(64);
    signature.set(r);
    signature.set(scalarBytes(nonce), 32);
    const body = canonical([protectedBytes, new Map(), payload, signature]);
    const cose = new Uint8Array(body.length + 1);
    cose[0] = 0xd2;
    cose.set(body, 1);
    return cose;
  }
}
