const path = require('path')
const assert = require('assert')
const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { plonk } = require('snarkjs')
const { stringifyBigInts, unstringifyBigInts } = require('ffjavascript').utils
const {
	toFixedHex,
	bitArrayToDecimal,
	generateMerkleProof,
	prepareSolidityCallData } = require('./utils')

class ApproveProver {
	wasmFile
	zKeyFile
	vKey

	constructor(wasmFile, zKeyFile, vKey) {
		this.wasmFile = wasmFile
		this.zKeyFile = zKeyFile
		this.vKey = unstringifyBigInts(vKey)
	}

	static async initialize(
		wasmFile = path.resolve(__dirname, "../build/approve12/approve12.wasm"),
		zKeyFile = path.resolve(__dirname, "../build/approve12/approve12.zkey"),
		vKey = require('../build/approve12/verification_key.json')) {
		return new ApproveProver(wasmFile, zKeyFile, vKey)
	}

	async generateSnarkProofFromContract(notary, hashFn, subjectAddr, credential) {
		const { root, pathElements, pathIndices } = await generateMerkleProof(notary, hashFn, credential.commitment)

		const isValidRoot = await notary.callStatic.isKnownRoot(toFixedHex(root))
		assert(isValidRoot === true, 'Merkle tree is corrupted')

		return await this.generateSnarkProof({ root, pathElements, pathIndices }, subjectAddr, credential)
	}

	prepareInputs(merkleProof, subjectAddr, credential) {
		return stringifyBigInts({
			root: merkleProof.root,
			nullifierHash: credential.nullifierHash,
			subject: BigNumber.from(subjectAddr).toBigInt(),
			nullifier: credential.nullifier,
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
			_subject: calldata.publicSignals[2],
		}
	}

	async generateSnarkProof(merkleProof, subjectAddr, credential) {
		const inputs = this.prepareInputs(merkleProof, subjectAddr, credential)

		console.log("\tgenerating snark proof...")
		return await plonk.fullProve(inputs, this.wasmFile, this.zKeyFile)
	}

	verificationKey() {
		return this.vKey
	}
}

module.exports = ApproveProver