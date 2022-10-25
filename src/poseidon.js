const { BigNumber } = require('hardhat').ethers
const { buildPoseidonReference } = require('circomlibjs')

class Poseidon {
	#hashFn

	constructor(hashFunction) {
		this.#hashFn = hashFunction
		this.F = hashFunction.F
	}

	static async initialize() {
		return new Poseidon(await buildPoseidonReference())
	}

	/**
	 * Hash items using Poseidon elliptic curve hash function
	 * @param {Array<BigNumber>} items Array of items to be hashed
	 */
	hash(items) {
		return this.F.toString(this.#hashFn(items.map((x) => BigNumber.from(x).toBigInt())))
	}

	/**
	 * Hash two elements using Poseidon elliptic curve hash function
	 * @param {BigNumber, BigNumber} elements to be hashed
	 */
	hash2(a, b) {
		return this.hash([a, b])
	}
}

module.exports = Poseidon