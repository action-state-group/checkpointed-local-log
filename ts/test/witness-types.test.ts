import { describe, expectTypeOf, it } from "vitest";

import { ReceiptVerifier, type ReceiptVerification } from "../src/index.js";

describe("ReceiptVerification", () => {
  it("accepts the async ReceiptVerifier as well as synchronous verifiers", () => {
    // Checked by `tsc --noEmit`: the README wires a ReceiptVerifier into
    // WitnessDeliveryRunner's verifiers map.
    expectTypeOf<ReceiptVerifier>().toMatchTypeOf<ReceiptVerification>();
    expectTypeOf<{
      verify: () => boolean;
    }>().toMatchTypeOf<ReceiptVerification>();
  });
});
