const path = require('path')
const { readFileSync } = require('fs')
const assert = require('assert')
const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { plonk } = require('snarkjs')
const { stringifyBigInts } = require('ffjavascript').utils
const {
	toFixedHex,
	bitArrayToDecimal,
	generateMerkleProof,
	prepareSolidityCallData } = require('./utils')

class ApproveProver {
	wasmFile
	zKeyFile
	vKeyFile

	constructor(wasmFile, zKeyFile, vKeyFile) {
		this.wasmFile = wasmFile
		this.zKeyFile = zKeyFile
		this.vKeyFile = vKeyFile
	}

	static async initialize(
		wasmFile = path.resolve(__dirname, "../build/approve12/approve12.wasm"),
		zKeyFile = path.resolve(__dirname, "../build/approve12/approve12.zkey"),
		vKeyFile = path.resolve(__dirname, "../build/approve12/verification_key.json")) {
		return new ApproveProver(wasmFile, zKeyFile, vKeyFile)
	}

	async generateSnarkProofFromContract(notary, hashFn, sender, credential) {
		const { root, pathElements, pathIndices } = await generateMerkleProof(notary, hashFn, credential.commitment)

		const isValidRoot = await notary.callStatic.isKnownRoot(toFixedHex(root))
		assert(isValidRoot === true, 'Merkle tree is corrupted')

		return await this.generateSnarkProof({ root, pathElements, pathIndices }, sender, credential)
	}

	prepareInputs(merkleProof, sender, credential) {
		return stringifyBigInts({
			root: merkleProof.root,
			nullifierHash: credential.nullifierHash,
			sender: BigNumber.from(sender).toBigInt(),
			nullifier: credential.root,
			subject: credential.subject,
			secret: credential.secret,
			pathElements: merkleProof.pathElements,
			pathIndices: bitArrayToDecimal(merkleProof.pathIndices).toString(),
		})
	}

	async prepareCallData(proofData, publicSignals) {
		const calldata = await prepareSolidityCallData(proofData, publicSignals)
		return {
			_proof: calldata.proof,
			_root: calldata.publicSignals[0],
			_nullifierHash: calldata.publicSignals[1],
			_sender: calldata.publicSignals[2],
		}
	}

	async generateSnarkProof(merkleProof, sender, credential) {
		const inputs = this.prepareInputs(merkleProof, sender, credential)

		console.log("\tgenerating snark proof...")
		return await plonk.fullProve(inputs, this.wasmFile, this.zKeyFile)
	}

	verificationKey() {
		return JSON.parse(readFileSync(this.vKeyFile).toString())
	}
}

module.exports = ApproveProver