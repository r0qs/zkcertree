const path = require("path")
const { expect } = require("chai")
const { buildEddsa } = require('circomlibjs')
const { utils } = require('ffjavascript')
const wasm_tester = require("circom_tester").wasm
const { MerkleTree } = require('fixed-merkle-tree')
const { toBuffer } = require('document-tree')
const { utils: { toUtf8Bytes, sha256 } } = require('hardhat').ethers

const Poseidon = require('../../src/poseidon')
const {
	ZERO_VALUE,
	randomBN,
	toFixedHex,
	prepareCertreeProofInputs,
	bufferToBigIntField,
	bitArrayToDecimal,
	generateDocuments
} = require("../../src/utils")

CERT_TREE_HEIGHT = 8

describe("Timeframe circuit", function () {
	this.timeout(25000)
	let circuit, poseidon

	function poseidonHash2(a, b) {
		return poseidon.hash([a, b])
	}

	function poseidonHash(items) {
		return poseidon.hash(items)
	}

	function getNewCertree(leaves = [], tree_height = CERT_TREE_HEIGHT, zero = ZERO_VALUE) {
		return new MerkleTree(tree_height, leaves, { hashFunction: poseidonHash2, zeroElement: zero })
	}

	function createCredential(secret, publicKey, root) {
		let credential = { secret, root }
		credential.subject = poseidonHash([eddsa.F.toObject(publicKey[0]), eddsa.F.toObject(publicKey[1])])
		credential.commitment = poseidonHash([credential.root, credential.subject, credential.secret])
		credential.nullifierHash = poseidonHash([credential.root])
		return credential
	}

	function prepareTimestampInputs(n, fieldKey, doctrees) {
		let fields = []
		let pathElements = new Array()
		let pathIndices = new Array()
		for (let i = 0; i < n; i++) {
			const leaf = doctrees[i].findLeaf(fieldKey)
			fields[i] = [
				bufferToBigIntField(toBuffer(leaf.key())),
				bufferToBigIntField(toBuffer(leaf.value)),
				bufferToBigIntField(toBuffer(leaf.salt))
			]

			const proof = doctrees[i].proof(fieldKey)
			expect(MerkleTree.verifyProof(
				doctrees[i].root(),
				doctrees[i].levels(),
				poseidonHash2,
				leaf.hash,
				proof.pathElements,
				proof.pathIndices
			)).to.be.true

			pathElements.push(proof.pathElements)
			pathIndices.push(bitArrayToDecimal(proof.pathIndices).toString())
		}

		return utils.stringifyBigInts({
			fields: fields,
			pathFieldElements: pathElements,
			pathFieldIndices: pathIndices,
		})
	}

	before(async () => {
		circuit = await wasm_tester(path.join(__dirname, "circuits", "timeframe_test.circom"))
		poseidon = await Poseidon.initialize()
		eddsa = await buildEddsa()
	})

	it("should check the timeframe of a set of credentials", async () => {
		const nCerts = 5
		const issuer = toFixedHex(randomBN())
		const subject = toFixedHex(randomBN())
		const privateKey = toFixedHex(randomBN())
		const publicKey = eddsa.prv2pub(privateKey)

		const docs = generateDocuments(nCerts, issuer, subject, poseidonHash2, poseidonHash)
		const leaves = docs.map(d => d.root())
		const certree = getNewCertree(leaves, CERT_TREE_HEIGHT, ZERO_VALUE)

		const credentials = []
		for (let i = 0; i < nCerts; i++) {
			credentials[i] = createCredential(randomBN().toString(), publicKey, docs[i].root())
			certree.insert(credentials[i].commitment)
		}

		const certProofs = prepareCertreeProofInputs(certree, credentials)
		const timestampProofInputs = prepareTimestampInputs(nCerts, "timestamp", docs)
		const fieldKey = bufferToBigIntField(toBuffer(sha256(toUtf8Bytes("timestamp")).replace('0x', '')))

		const intervals = docs.map(d => d.findLeaf("timestamp").value)
		const duration = intervals[nCerts - 1] - intervals[0]
		const period = duration + 1

		const inputs = utils.stringifyBigInts({
			certreeRoot: certree.root,
			nullifierHashes: credentials.map(c => c.nullifierHash),
			timestampFieldKey: fieldKey,
			period: period,
			operator: 5n, // <=
			credentialRoots: credentials.map(c => c.root),
			subjects: credentials.map(c => c.subject),
			secrets: credentials.map(c => c.secret),
			pathCertreeElements: certProofs.map(p => p.pathCertreeElements),
			pathCertreeIndices: certProofs.map(p => p.pathCertreeIndices),
			...timestampProofInputs
		})

		const w = await circuit.calculateWitness(inputs, true)
		await circuit.checkConstraints(w)
	});
})