const { BigNumber } = require('hardhat').ethers
const { buildPoseidonReference } = require('circomlibjs')

class Poseidon {
	#hashFn

	constructor(hashFunction) {
		this.#hashFn = hashFunction
	}

	static async initialize() {
		return new Poseidon(await buildPoseidonReference())
	}

	/**
	 * Hash items using Poseidon elliptic curve hash function
	 * @param {Array<BigNumber>} items Array of items to be hashed
	 */
	hash(items) {
		return this.#hashFn.F.toString(this.#hashFn(items.map((x) => BigNumber.from(x).toBigInt())))
	}
}

module.exports = Poseidon