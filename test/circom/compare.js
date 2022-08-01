const path = require("path")
const wasm_tester = require("circom_tester").wasm
const assert = require('assert')

describe("Compare circuit", function () {
	this.timeout(25000)
	let circuit

	before(async () => {
		circuit = await wasm_tester(path.join(__dirname, "circuits", "compare_test.circom"))
	})

	const tests = [
		{
			name: "equal (true)",
			a: 1,
			b: 1,
			op: 0,
			expected: 1
		},
		{
			name: "equal (false)",
			a: 1,
			b: 2,
			op: 0,
			expected: 0
		},
		{
			name: "different (true)",
			a: 1,
			b: 2,
			op: 1,
			expected: 1
		},
		{
			name: "different (false)",
			a: 1,
			b: 1,
			op: 1,
			expected: 0
		},
		{
			name: "greater than (true)",
			a: 3,
			b: 2,
			op: 2,
			expected: 1
		},
		{
			name: "greater than (false - equal)",
			a: 2,
			b: 2,
			op: 2,
			expected: 0
		},
		{
			name: "greater than (false - less)",
			a: 1,
			b: 2,
			op: 2,
			expected: 0
		},
		{
			name: "greater than or equal (true - equal)",
			a: 2,
			b: 2,
			op: 3,
			expected: 1
		},
		{
			name: "greater than or equal (true - greater)",
			a: 3,
			b: 2,
			op: 3,
			expected: 1
		},
		{
			name: "greater than or equal (false)",
			a: 2,
			b: 3,
			op: 3,
			expected: 0
		},
		{
			name: "less than (true)",
			a: 2,
			b: 3,
			op: 4,
			expected: 1
		},
		{
			name: "less than (false - equal)",
			a: 2,
			b: 2,
			op: 4,
			expected: 0
		},
		{
			name: "less than (false - greater)",
			a: 2,
			b: 1,
			op: 4,
			expected: 0
		},
		{
			name: "less than or equal (true - less)",
			a: 0,
			b: 1,
			op: 5,
			expected: 1
		},
		{
			name: "less than or equal (true - equal)",
			a: 1,
			b: 1,
			op: 5,
			expected: 1
		},
		{
			name: "less than or equal (false)",
			a: 2,
			b: 1,
			op: 5,
			expected: 0
		}
	]

	tests.forEach((test) => {
		it(test.name, async () => {
			const w = await circuit.calculateWitness({
				a: test.a,
				b: test.b,
				op: test.op
			}, true)

			await circuit.checkConstraints(w)
			await circuit.assertOut(w, { out: test.expected })
		})
	})

	it("should fail with an invalid operator", async () => {
		await assert.rejects(async () => {
			await circuit.calculateWitness({
				a: 2,
				b: 2,
				op: 6
			}, true)
		}, /Error: Assert Failed/)
	})
})