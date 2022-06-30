const path = require('path')
const assert = require('assert')
const { plonk } = require('snarkjs')
const { stringifyBigInts, unstringifyBigInts } = require('ffjavascript').utils
const { buildEddsa } = require('circomlibjs')

class IssueProver {
	wasmFile
	zKeyFile
	vKey
	eddsa

	constructor(wasmFile, zKeyFile, vKey, eddsa) {
		this.wasmFile = wasmFile
		this.zKeyFile = zKeyFile
		this.vKey = unstringifyBigInts(vKey)
		this.eddsa = eddsa
	}

	static async initialize(
		wasmFile = path.resolve(__dirname, "../build/issue/issue.wasm"),
		zKeyFile = path.resolve(__dirname, "../build/issue/issue.zkey"),
		vKey = require('../build/issue/verification_key.json')) {
		return new IssueProver(wasmFile, zKeyFile, vKey, await buildEddsa())
	}

	prepareInputs(credential, signature, publicKey) {
		return stringifyBigInts({
			nullifierHash: credential.nullifierHash,
			commitment: credential.commitment,
			publicKey: [
				this.eddsa.F.toObject(publicKey[0]),
				this.eddsa.F.toObject(publicKey[1])
			],
			nullifier: credential.nullifier,
			secret: credential.secret,
			signature: [
				this.eddsa.F.toObject(signature.R8[0]),
				this.eddsa.F.toObject(signature.R8[1]),
				signature.S
			],
		})
	}

	async generateSnarkProof(credential, signature, publicKey) {
		assert(this.eddsa.verifyPoseidon(credential.commitment, signature, publicKey))
		const inputs = this.prepareInputs(credential, signature, publicKey)

		console.log("\tgenerating snark proof...")
		return await plonk.fullProve(inputs, this.wasmFile, this.zKeyFile)
	}

	verificationKey() {
		return this.vKey
	}
}

module.exports = IssueProver