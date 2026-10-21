/*
 * Recipient address -> BN254 field element (architecture decision D4).
 *
 *   recipient = sha256(XDR of the address as an ScVal), top 3 bits cleared
 *
 * Clearing 3 bits leaves a 253-bit value, always below the BN254 field modulus.
 * Must match recipient_to_field() in contracts/shield-vault/src/lib.rs exactly;
 * both are checked against test-vectors/recipient.json.
 */
const crypto = require("crypto");
const { Address } = require("@stellar/stellar-base");

/**
 * Encodes a Stellar address (G... account or C... contract) as a field element.
 *
 * @param {string} address Stellar strkey address.
 * @returns {bigint} The recipient public input for the claim circuit.
 */
function addressToField(address) {
    const xdr = Address.fromString(address).toScVal().toXDR();
    const hash = crypto.createHash("sha256").update(xdr).digest();
    hash[0] &= 0x1f; // Keep 253 bits so the value is a canonical field element
    return BigInt("0x" + hash.toString("hex"));
}

module.exports = { addressToField };
