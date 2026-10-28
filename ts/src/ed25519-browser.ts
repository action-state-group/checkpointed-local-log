// Ed25519 verification for the browser entry, on @noble/curves in every
// browser. WebCrypto's Ed25519 is not used: Chrome's accepts a signature by a
// small-order public key, which anyone can make without a private key and
// which Node refuses (test/browser/checkpoint.browser-test.ts), and the
// engines need not agree with each other. SubtleCrypto is also missing
// outside a secure context.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

const { Point } = ed25519;

const littleEndian = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1)
    value = (value << 8n) | BigInt(bytes[i]!);
  return value;
};

/**
 * RFC 8032 section 5.1.7 verification that refuses: non-canonical encodings
 * of A or R (y >= p), A or R of small order, S >= L, and any signature
 * failing the cofactorless equation [S]B = R + [k]A. Node's OpenSSL refuses
 * each of those too (test/browser-checkpoint.test.ts), so this accepts no
 * signature the Node entry refuses. noble's own `verify` checks the
 * cofactored equation instead, which accepts a signer-made R with a
 * small-order component that OpenSSL refuses, so it is not used.
 */
export function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const r = signature.subarray(0, 32);
  const s = littleEndian(signature.subarray(32));
  if (s >= Point.Fn.ORDER) return false;
  let a: InstanceType<typeof Point>;
  let rPoint: InstanceType<typeof Point>;
  try {
    a = Point.fromBytes(publicKey, false);
    rPoint = Point.fromBytes(r, false);
  } catch {
    return false;
  }
  if (a.isSmallOrder() || rPoint.isSmallOrder()) return false;
  const digest = new Uint8Array(64 + message.length);
  digest.set(r);
  digest.set(publicKey, 32);
  digest.set(message, 64);
  const k = littleEndian(sha512(digest)) % Point.Fn.ORDER;
  return Point.BASE.multiplyUnsafe(s).equals(rPoint.add(a.multiplyUnsafe(k)));
}
