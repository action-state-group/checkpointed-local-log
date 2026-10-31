import { describe, expect, it } from "vitest";

import { CborMap, CborTag, decodeReceiptItem } from "../src/cbor-strict.js";
import { fromHex } from "./browser-checkpoint-cases.js";

describe("decodeReceiptItem", () => {
  it.each([
    ["trailing byte", "0000"],
    ["truncated", "1a0001"],
    ["non-shortest argument", "1801"],
    ["reserved length", "1c"],
    ["indefinite array", "9f01ff"],
    ["indefinite text", "7f6161ff"],
    ["half float", "f93c00"],
    ["double", "fb3ff0000000000000"],
    ["undefined", "f7"],
    ["simple value 0", "e0"],
    ["simple value 32", "f820"],
    ["bignum", "c249010000000000000000"],
    ["integer below -2^63", "3bffffffffffffffff"],
    ["byte-string key", "a1416b01"],
    ["array key", "a1810101"],
    ["repeated key", "a201010102"],
    ["repeated text key", "a2616101616102"],
    ["inner tag 18", "81d280"],
    ["invalid UTF-8", "61ff"],
    ["array longer than the input", "9a0000ffff00"],
    ["17 levels", `${"81".repeat(17)}00`],
  ])("refuses %s", (_, item) => {
    expect(() => decodeReceiptItem(fromHex(item), true)).toThrow();
  });

  it("refuses tag 18 where no tag is allowed", () => {
    expect(() => decodeReceiptItem(fromHex("d280"), false)).toThrow(
      SyntaxError,
    );
  });

  it("accepts what the rule admits", () => {
    expect(decodeReceiptItem(fromHex(`${"81".repeat(16)}00`), false)).toEqual(
      JSON.parse(`${"[".repeat(16)}0${"]".repeat(16)}`, (_, v: unknown) =>
        typeof v === "number" ? BigInt(v) : v,
      ),
    );
    expect(decodeReceiptItem(fromHex("83f6f4f5"), false)).toEqual([
      null,
      false,
      true,
    ]);
    expect(decodeReceiptItem(fromHex("3b7fffffffffffffff"), false)).toBe(
      -(1n << 63n),
    );
    const map = decodeReceiptItem(fromHex("a2616201616102"), false);
    expect(map).toBeInstanceOf(CborMap);
    expect((map as CborMap).get("a")).toBe(2n);
    const tagged = decodeReceiptItem(fromHex("d28140"), true);
    expect(tagged).toEqual(new CborTag(18n, [new Uint8Array()]));
  });
});
