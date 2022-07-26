const path = require("path")
const { stringifyBigInts } = require('ffjavascript').utils
const wasm_tester = require("circom_tester").wasm
const { MerkleTree } = require('fixed-merkle-tree')
const Poseidon = require('../../src/poseidon')

const ZERO_VALUE = 0
const MERKLE_TREE_HEIGHT = 12

describe("Multiproof circuit", function () {
	this.timeout(25000)
	let circuit

	function poseidonHash(items) {
		return poseidon.hash(items)
	}

	function poseidonHash2(a, b) {
		return poseidonHash([a, b])
	}

	function getNewTree(leaves = [], tree_height = MERKLE_TREE_HEIGHT, zero = ZERO_VALUE) {
		return new MerkleTree(tree_height, leaves, { hashFunction: poseidonHash2, zeroElement: zero })
	}

	function prepareMultiproofInputs(tree_height, leaves, multiproof) {
		const n = 1 << tree_height
		const pathElements = multiproof.pathElements
		const leafIndices = multiproof.leafIndices

		return stringifyBigInts({
			leaves: leaves.concat(Array(n - leaves.length).fill(0)),
			pathElements: pathElements.concat(Array(n - pathElements.length).fill(0)),
			leafIndices: leafIndices.concat(Array(n - leafIndices.length).fill(0)),
		})
	}

	before(async () => {
		circuit = await wasm_tester(path.join(__dirname, "circuits", "multiproof_test.circom"))
		poseidon = await Poseidon.initialize()
	})

	const tests = [
		{
			name: "1st element",
			treeHeight: 3,
			leaves: [1]
		},
		{
			name: "4th element",
			treeHeight: 3,
			leaves: [4]
		},
		{
			name: "8th element",
			treeHeight: 3,
			leaves: [8]
		},
		{
			name: "1st neighbors",
			treeHeight: 3,
			leaves: [1, 2]
		},
		{
			name: "3rd neighbors",
			treeHeight: 3,
			leaves: [5, 6]
		},
		{
			name: "left subtree",
			treeHeight: 3,
			leaves: [1, 2, 3, 4]
		},
		{
			name: "right subtree",
			treeHeight: 3,
			leaves: [5, 6, 7, 8]
		},
		{
			name: "odd positions",
			treeHeight: 3,
			leaves: [1, 3, 5, 7]
		},
		{
			name: "even positions",
			treeHeight: 3,
			leaves: [2, 4, 6, 8]
		},
		{
			name: "1st, 2nd and 6th",
			treeHeight: 3,
			leaves: [1, 2, 6]
		},
		{
			name: "1st, 4th and 6th",
			treeHeight: 3,
			leaves: [1, 4, 6]
		},
		{
			name: "3rd, 5th and 6th",
			treeHeight: 3,
			leaves: [3, 5, 6]
		},
		{
			name: "2nd, 7th",
			treeHeight: 3,
			leaves: [2, 7]
		},
		{
			name: "1st, 5th",
			treeHeight: 3,
			leaves: [1, 5]
		},
		{
			name: "all",
			treeHeight: 3,
			leaves: [1, 2, 3, 4, 5, 6, 7, 8]
		},
	]

	tests.forEach((test) => {
		it(test.name, async () => {
			const allLeaves = [...Array(1 << test.treeHeight)].map((_, i) => i + 1)
			const tree = getNewTree(allLeaves, test.treeHeight)
			const proof = tree.multiProof(test.leaves)
			const inputs = prepareMultiproofInputs(test.treeHeight, test.leaves, proof)
			const w = await circuit.calculateWitness({
				leaves: inputs.leaves,
				pathElements: inputs.pathElements,
				leafIndices: inputs.leafIndices
			}, true)

			await circuit.checkConstraints(w)
			await circuit.assertOut(w, { root: tree.root })
		})
	})
})