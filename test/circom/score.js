const path = require("path")
const { expect } = require("chai")
const { buildEddsa } = require('circomlibjs')
const { utils } = require('ffjavascript')
const wasm_tester = require("circom_tester").wasm
const { MerkleTree } = require('fixed-merkle-tree')
const { toBuffer } = require('document-tree')

const Poseidon = require('../../src/poseidon')
const {
	ZERO_VALUE,
	randomBN,
	toFixedHex,
	prepareCertreeProofInputs,
	bufferToBigIntField,
	generateDocuments,
	weightedSum
} = require("../../src/utils")

CERT_TREE_HEIGHT = 8
CRED_TREE_HEIGHT = 3

describe("Score circuit", function () {
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

	// FIXME: dry
	function createCredential(secret, publicKey, root) {
		let credential = { secret, root }
		credential.subject = poseidonHash([eddsa.F.toObject(publicKey[0]), eddsa.F.toObject(publicKey[1])])
		credential.commitment = poseidonHash([credential.root, credential.subject, credential.secret])
		credential.nullifierHash = poseidonHash([credential.root])
		return credential
	}

	function prepareCredInputs(n, proofFieldKeys, credtreeHeight, doctrees) {
		const m = 1 << credtreeHeight

		let fields = []
		let pathElements = new Array()
		let leafIndices = new Array()
		// TODO: validate schema. Fields must be sorted by the schema
		proofFieldKeys.sort()
		const emptyEntry = Array(m - proofFieldKeys.length).fill([0n, 0n, 0n])
		for (let i = 0; i < n; i++) {
			fields[i] = new Array()
			for (let j = 0; j < proofFieldKeys.length; j++) {
				fields[i][j] = new Array()
				const leaf = doctrees[i].findLeaf(proofFieldKeys[j])
				fields[i][j][0] = bufferToBigIntField(toBuffer(leaf.key()))
				fields[i][j][1] = bufferToBigIntField(toBuffer(leaf.value))
				fields[i][j][2] = bufferToBigIntField(toBuffer(leaf.salt))
			}
			// TODO: multi proof by key or name
			const multiProof = doctrees[i].multiProof(proofFieldKeys)

			expect(MerkleTree.verifyMultiProof(
				doctrees[i].root(),
				doctrees[i].levels(),
				poseidonHash2,
				doctrees[i].leafHashes(proofFieldKeys),
				multiProof.pathElements,
				multiProof.leafIndices
			)).to.be.true

			const pe = multiProof.pathElements
			const li = multiProof.leafIndices
			pathElements.push(pe.concat(Array(m - pe.length).fill(0)))
			leafIndices.push(li.concat(Array(m - li.length).fill(0)))
			fields[i] = fields[i].concat(emptyEntry)
		}

		return utils.stringifyBigInts({
			fields: fields,
			pathFieldElements: pathElements,
			fieldIndices: leafIndices,
		})
	}

	before(async () => {
		circuit = await wasm_tester(path.join(__dirname, "circuits", "score_test.circom"))
		poseidon = await Poseidon.initialize()
		eddsa = await buildEddsa()
	})

	it("should compute the correct score of multiple credential's fields", async () => {
		const nCerts = 5
		const issuer = toFixedHex(randomBN())
		const subject = toFixedHex(randomBN())
		const privateKey = toFixedHex(randomBN())
		const publicKey = eddsa.prv2pub(privateKey)

		const docs = generateDocuments(nCerts, issuer, subject,  poseidonHash2, poseidonHash)
		const leaves = docs.map(d => d.root())
		const certree = getNewCertree(leaves, CERT_TREE_HEIGHT, ZERO_VALUE)

		const credentials = []
		for (let i = 0; i < nCerts; i++) {
			credentials[i] = createCredential(randomBN().toString(), publicKey, docs[i].root())
			certree.insert(credentials[i].commitment)
		}

		const certProofs = prepareCertreeProofInputs(certree, credentials)
		const credProofInputs = prepareCredInputs(nCerts, ["tag", "grade"], CRED_TREE_HEIGHT, docs)
		const tags = docs.map(d => bufferToBigIntField(toBuffer(d.findLeaf("tag").value)))
		const weights = [...Array(nCerts)].map((_, i) => (i % 2) + 1)
		const grades = docs.map(d => d.findLeaf("grade").value)
		const result = weightedSum(grades, weights)

		const inputs = utils.stringifyBigInts({
			certreeRoot: certree.root,
			requiredTags: tags,
			weights: weights,
			result: result,
			nullifierHashes: credentials.map(c => c.nullifierHash),
			credentialRoots: credentials.map(c => c.root),
			subjects: credentials.map(c => c.subject),
			secrets: credentials.map(c => c.secret),
			pathCertreeElements: certProofs.map(p => p.pathCertreeElements),
			pathCertreeIndices: certProofs.map(p => p.pathCertreeIndices),
			...credProofInputs
		})

		const w = await circuit.calculateWitness(inputs, true)
		await circuit.checkConstraints(w)
	});
})