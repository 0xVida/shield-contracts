const { expect } = require("chai");
const vectors = require("../test-vectors/recipient.json");
const { Address } = require("@stellar/stellar-base");
const { addressToField } = require("../lib/recipient");

/*
 * Recipient encoding tests (D4). The same vectors are checked on the contract side
 * in contracts/shield-vault/src/test.rs, so passing both proves JS and Rust agree.
 */
describe("Recipient Address Encoding", () => {
    for (const v of vectors.vectors) {
        it(`should match the shared vector for a ${v.kind} address`, () => {
            // Same XDR bytes as Soroban's Address::to_xdr
            const xdr = Address.fromString(v.address).toScVal().toXDR("hex");
            expect(xdr).to.equal(v.xdr);

            const field = addressToField(v.address);
            expect(field).to.equal(BigInt(v.field));
            expect(field.toString()).to.equal(v.fieldDecimal);
        });
    }

    it("should always fit in 253 bits", () => {
        for (const v of vectors.vectors) {
            expect(addressToField(v.address) < 2n ** 253n).to.be.true;
        }
    });

    it("should give different fields for different addresses", () => {
        const [a, b] = vectors.vectors.map((v) => addressToField(v.address));
        expect(a).to.not.equal(b);
    });
});
