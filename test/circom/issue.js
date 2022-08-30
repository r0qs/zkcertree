const assert = require('assert')
const wasm_tester = require("circom_tester").wasm
const { buildEddsa } = require('circomlibjs')
const Poseidon = require('../../src/poseidon')

const {
	randomBN
} = require('../../src/utils')

describe("Issue circuit", function () {
	this.timeout(25000)
	let circuit, eddsa, poseidon
	let secret, credentialRoot, privateKey

	function poseidonHash(items) {
		return poseidon.hash(items)
	}

	function createCredential(secret, publicKey, root) {
		let credential = { secret, root }
		credential.subject = poseidonHash([eddsa.F.toObject(publicKey[0]), eddsa.F.toObject(publicKey[1])])
		credential.commitment = poseidonHash([credential.root, credential.subject, credential.secret])
		credential.nullifierHash = poseidonHash([credential.root])
		return credential
	}

	before(async () => {
		circuit = await wasm_tester("./circuits/issue.circom")
		poseidon = await Poseidon.initialize()
		eddsa = await buildEddsa()

		secret = randomBN().toString()
		credentialRoot = randomBN().toString()
		privateKey = randomBN().toString()
	})

	it("should successfully generate a valid issuance proof", async () => {
		const publicKey = eddsa.prv2pub(privateKey)
		const credential = createCredential(secret, publicKey, credentialRoot)
		const signature = eddsa.signPoseidon(privateKey, eddsa.F.e(credential.commitment))

		const w = await circuit.calculateWitness({
			commitment: credential.commitment,
			credentialRoot: credential.root,
			publicKey: [
				eddsa.F.toObject(publicKey[0]),
				eddsa.F.toObject(publicKey[1])
			],
			secret: credential.secret,
			signature: [
				eddsa.F.toObject(signature.R8[0]),
				eddsa.F.toObject(signature.R8[1]),
				signature.S
			],
		}, true)

		await circuit.checkConstraints(w)
	})

	it("should not generate a valid proof from a invalid signer", async () => {
		const publicKey = eddsa.prv2pub(privateKey)
		const credential = createCredential(secret, publicKey, credentialRoot)
		const signature = eddsa.signPoseidon(randomBN().toString(), eddsa.F.e(credential.commitment))

		const w = circuit.calculateWitness({
			commitment: credential.commitment,
			credentialRoot: credential.root,
			publicKey: [
				eddsa.F.toObject(publicKey[0]),
				eddsa.F.toObject(publicKey[1])
			],
			secret: credential.secret,
			signature: [
				eddsa.F.toObject(signature.R8[0]),
				eddsa.F.toObject(signature.R8[1]),
				signature.S
			],
		}, true)

		await assert.rejects(async () => { await w }, /Error: Assert Failed/)
	})

	it("should not accept trivial commitments", async () => {
		const publicKey = eddsa.prv2pub(privateKey)
		const credential = createCredential(secret, publicKey, credentialRoot)
		const signature = eddsa.signPoseidon(publicKey, eddsa.F.e(credential.commitment))

		const w = circuit.calculateWitness({
			commitment: 0,
			credentialRoot: credential.root,
			publicKey: [
				eddsa.F.toObject(publicKey[0]),
				eddsa.F.toObject(publicKey[1])
			],
			secret: credential.secret,
			signature: [
				eddsa.F.toObject(signature.R8[0]),
				eddsa.F.toObject(signature.R8[1]),
				signature.S
			],
		}, true)

		await assert.rejects(async () => { await w }, /Error: Assert Failed/)
	})

	it("should not validate a commitment from the wrong subject", async () => {
		const signerPublicKey = eddsa.prv2pub(privateKey)
		const credential = createCredential(secret, signerPublicKey, credentialRoot)

		const wrongPublicKey = eddsa.prv2pub(randomBN().toString())
		const signature = eddsa.signPoseidon(wrongPublicKey, eddsa.F.e(credential.commitment))

		const w = circuit.calculateWitness({
			commitment: credential.commitment,
			credentialRoot: credential.root,
			publicKey: [
				eddsa.F.toObject(wrongPublicKey[0]),
				eddsa.F.toObject(wrongPublicKey[1])
			],
			secret: credential.secret,
			signature: [
				eddsa.F.toObject(signature.R8[0]),
				eddsa.F.toObject(signature.R8[1]),
				signature.S
			],
		}, true)

		await assert.rejects(async () => { await w }, /Error: Assert Failed/)
	})
})