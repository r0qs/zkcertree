const { buildPoseidonReference } = require('circomlibjs')

class Poseidon {
	#hashFn

	constructor(hashFunction) {
		this.#hashFn = hashFunction
	}

	static async initialize() {
		return new Poseidon(await buildPoseidonReference())
	}

	hash(items) {
		return this.#hashFn.F.toString(this.#hashFn(items))
	}
}

module.exports = Poseidon