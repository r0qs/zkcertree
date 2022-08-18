const path = require("path")
const assert = require('assert')
const wasm_tester = require("circom_tester").wasm
const { buildEddsa, buildPoseidonReference } = require('circomlibjs')
const { MerkleTree } = require('fixed-merkle-tree')
const { BigNumber } = require('hardhat').ethers

const {
	ZERO_VALUE,
	randomBN,
	bitArrayToDecimal
} = require('../../src/utils')

const CERT_TREE_HEIGHT = 8

describe("Approve circuit", function () {
	this.timeout(25000)
	let circuit, eddsa, poseidon, credential

	function poseidonHash(items) {
		return poseidon.F.toString(poseidon(items.map((x) => BigNumber.from(x).toBigInt())))
	}

	function poseidonHash2(a, b) {
		return poseidonHash([a, b])
	}

	function getNewTree(leaves = [], tree_height = CERT_TREE_HEIGHT, zero = ZERO_VALUE) {
		return new MerkleTree(tree_height, leaves, { hashFunction: poseidonHash2, zeroElement: zero })
	}

	function createCredential(secret, publicKey, root) {
		let credential = { secret, root }
		credential.subject = poseidonHash2(eddsa.F.toObject(publicKey[0]), eddsa.F.toObject(publicKey[1]))
		credential.commitment = poseidonHash([credential.root, credential.subject, credential.secret])
		credential.nullifierHash = poseidonHash([credential.root])
		return credential
	}

	before(async () => {
		circuit = await wasm_tester(path.join(__dirname, "circuits", "approve_test.circom"))
		eddsa = await buildEddsa()
		poseidon = await buildPoseidonReference()

		const secret = randomBN().toString()
		const credentialRoot = randomBN().toString()
		const publicKey = eddsa.prv2pub(secret)
		credential = createCredential(secret, publicKey, credentialRoot)
	})

	it("should successfully generate a valid approval proof", async () => {
		const tree = getNewTree()
		tree.insert(credential.commitment)
		const { pathElements, pathIndices } = tree.proof(credential.commitment)

		const w = await circuit.calculateWitness({
			root: tree.root,
			nullifierHash: credential.nullifierHash,
			sender: randomBN().toString(),
			nullifier: credential.root,
			subject: credential.subject,
			secret: credential.secret,
			pathElements: pathElements,
			pathIndices: bitArrayToDecimal(pathIndices).toString(),
		}, true)

		await circuit.checkConstraints(w)
	})

	it("should not generate a valid approval proof for invalid merkle proof", async () => {
		const tree = getNewTree()
		const somethingElse = randomBN().toString()
		tree.insert(somethingElse)
		const { pathElements, pathIndices } = tree.proof(somethingElse)

		const w = circuit.calculateWitness({
			root: tree.root,
			nullifierHash: credential.nullifierHash,
			sender: randomBN().toString(),
			nullifier: credential.root,
			subject: credential.subject,
			secret: credential.secret,
			pathElements: pathElements,
			pathIndices: bitArrayToDecimal(pathIndices).toString(),
		}, true)

		await assert.rejects(async () => { await w }, /Error: Assert Failed/)
	})

	it("should not generate a valid approval proof for invalid nullifier hash", async () => {
		const tree = getNewTree()
		tree.insert(credential.commitment)
		const { pathElements, pathIndices } = tree.proof(credential.commitment)

		const w = circuit.calculateWitness({
			root: tree.root,
			nullifierHash: randomBN().toString(),
			sender: randomBN().toString(),
			nullifier: credential.root,
			subject: credential.subject,
			secret: credential.secret,
			pathElements: pathElements,
			pathIndices: bitArrayToDecimal(pathIndices).toString(),
		}, true)

		await assert.rejects(async () => { await w }, /Error: Assert Failed/)
	})

	it("should not generate a valid approval proof for invalid root", async () => {
		const tree = getNewTree()
		tree.insert(credential.commitment)
		const { pathElements, pathIndices } = tree.proof(credential.commitment)

		const w = circuit.calculateWitness({
			root: randomBN().toString(),
			nullifierHash: credential.nullifierHash,
			sender: randomBN().toString(),
			nullifier: credential.root,
			subject: credential.subject,
			secret: credential.secret,
			pathElements: pathElements,
			pathIndices: bitArrayToDecimal(pathIndices).toString(),
		}, true)

		await assert.rejects(async () => { await w }, /Error: Assert Failed/)
	})
})