
const path = require('path')
const hre = require('hardhat')
const { ethers, waffle } = hre
const { loadFixture } = waffle
const { BigNumber, utils } = ethers
const { expect } = require('chai')
const createBlakeHash = require("blake-hash")
const { wtns, plonk } = require('snarkjs')
const { buildEddsa, buildBabyjub } = require('circomlibjs')
const { unstringifyBigInts, stringifyBigInts, leBuff2int } = require('ffjavascript').utils

const { MerkleTree } = require('fixed-merkle-tree')
const { prepareApproveCallData, bitArrayToDecimal, toFixedHex, deploy, FIELD_SIZE } = require('../../src/utils')
const { randomBN } = require('./utils')
const Poseidon = require('../../src/poseidon')

const DEFAULT_ZERO_VALUE = 0
const MERKLE_TREE_HEIGHT = 12

describe('PrivateNotary', function () {
	const basePath = path.resolve(__dirname, "../../build")

	before(async () => {
		eddsa = await buildEddsa()
		babyJub = await buildBabyjub()
		poseidon = await Poseidon.initialize()
		issueWasmFile = basePath.concat('/issue/issue.wasm')
		issueZKeyFile = basePath.concat('/issue/issue.zkey')
		issueVKey = unstringifyBigInts(require('../../build/issue/verification_key.json'))
		approveWasmFile = basePath.concat('/approve/approve.wasm')
		approveZKeyFile = basePath.concat('/approve/approve.zkey')
		approveVKey = unstringifyBigInts(require('../../build/approve/verification_key.json'))
	})

	function poseidonHash(items) {
		return poseidon.hash(items)
	}

	function poseidonHash2(a, b) {
		return poseidonHash([a, b])
	}

	function getNewTree(tree_height = MERKLE_TREE_HEIGHT, zero = DEFAULT_ZERO_VALUE) {
		return new MerkleTree(tree_height, [], { hashFunction: poseidonHash2, zeroElement: zero })
	}

	function createCredential(secret, nullifier, tree, idx) {
		let credential = { secret, nullifier }
		credential.commitment = poseidonHash2(credential.nullifier, credential.secret)
		credential.nullifierHash = poseidonHash([credential.nullifier])

		tree.insert(credential.commitment)
		const { pathElements, pathIndices } = tree.path(idx)
		credential.pathElements = pathElements
		credential.pathIndices = pathIndices

		return credential
	}

	async function generateIssueSnarkProof(credential, signature, publicKey) {
		const inputs = stringifyBigInts({
			nullifierHash: credential.nullifierHash,
			credentialCommitment: credential.commitment,
			publicKey: [
				babyJub.F.toObject(publicKey[0]),
				babyJub.F.toObject(publicKey[1])
			],
			nullifier: credential.nullifier,
			secret: credential.secret,
			signature: [
				babyJub.F.toObject(signature.R8[0]),
				babyJub.F.toObject(signature.R8[1]),
				signature.S
			],
		})

		console.log("\tgenerating snark proof...")
		return await plonk.fullProve(inputs, issueWasmFile, issueZKeyFile)
	}

	async function generateApproveSnarkProof(root, subjectAddr, credential) {
		const inputs = stringifyBigInts({
			root: root,
			nullifierHash: credential.nullifierHash,
			subject: BigNumber.from(subjectAddr).toString(),
			nullifier: credential.nullifier,
			secret: credential.secret,
			pathElements: credential.pathElements,
			pathIndices: bitArrayToDecimal(credential.pathIndices).toString(),
		})

		// TODO: mock test proofs
		console.log("\tgenerating snark proof...")
		return await plonk.fullProve(inputs, approveWasmFile, approveZKeyFile)
	}

	async function fixture(tree_height = MERKLE_TREE_HEIGHT) {
		require('../../scripts/compile_hasher')

		const [multisig, sender1, sender2] = await ethers.getSigners()
		const approveVerifier = await deploy('ApproveVerifier')
		const hasher = await deploy('Hasher')
		const pvtNotaryImpl = await deploy(
			'PrivateNotaryMock',
			approveVerifier.address,
			tree_height,
			hasher.address,
			multisig.address
		)

		return { pvtNotaryImpl, approveVerifier, hasher, multisig, sender1, sender2 }
	}

	describe('#constructor', () => {
		it('should initialize', async () => {
			const { pvtNotaryImpl, approveVerifier, hasher, multisig } = await loadFixture(fixture)
			const tree = getNewTree()

			expect(await pvtNotaryImpl.multisig()).to.equal(multisig.address)
			expect(await pvtNotaryImpl.verifier()).to.equal(approveVerifier.address)
			expect(await pvtNotaryImpl.hasher()).to.equal(hasher.address)
			expect(await pvtNotaryImpl.getLastRoot()).to.equal(toFixedHex(tree.root))
			expect(await pvtNotaryImpl.levels()).to.equal(MERKLE_TREE_HEIGHT)
			expect(await pvtNotaryImpl.levels()).to.equal(tree.levels)
			expect(await pvtNotaryImpl.FIELD_SIZE()).to.equal(FIELD_SIZE)
			expect(await pvtNotaryImpl.ZERO_VALUE()).to.equal(DEFAULT_ZERO_VALUE)
		})
	})

	describe('#issue', () => {
		it('should register a credential commitment', async () => {
			const { pvtNotaryImpl, multisig } = await loadFixture(fixture)
			const tree = getNewTree()

			const commitment = toFixedHex(42)
			const tx = await pvtNotaryImpl.connect(multisig).issue(commitment)
			await tx.wait();

			expect(await pvtNotaryImpl.commitments(commitment)).to.be.true

			tree.insert(42)
			expect(await pvtNotaryImpl.getLastRoot()).to.equal(toFixedHex(tree.root))
		})

		it('should not allow registration from non multisig sender', async () => {
			const { pvtNotaryImpl, sender1 } = await loadFixture(fixture)

			await expect(pvtNotaryImpl.connect(sender1).issue(toFixedHex(42)))
				.to.be.revertedWith("Only multisig")
		})

		it('should emit event', async () => {
			const { pvtNotaryImpl, multisig } = await loadFixture(fixture)
			const commitment = toFixedHex(42)

			await pvtNotaryImpl.connect(multisig).issue(commitment)

			const filter = pvtNotaryImpl.filters.CredentialCreated()
			const fromBlock = await ethers.provider.getBlock()
			const events = await pvtNotaryImpl.queryFilter(filter, fromBlock.number)

			expect(events).to.not.be.empty
			expect(events).to.have.length(1)
			expect(events[0].event).to.equal("CredentialCreated")
			expect(events[0].args.commitment).to.equal(commitment)
			expect(events[0].args.index).to.equal(0)
			expect(events[0].args.timestamp).to.equal(fromBlock.timestamp)
		})

		it('should not register an already registered commitment', async () => {
			const { pvtNotaryImpl, multisig } = await loadFixture(fixture)
			const commitment = toFixedHex(42)

			await pvtNotaryImpl.connect(multisig).issue(commitment)

			await expect(pvtNotaryImpl.connect(multisig).issue(commitment))
				.to.be.revertedWith("Commitment already registered")
		})
	})

	describe('#approve', () => {
		it('should issue a credential upon approval and emit event', async () => {
			const { pvtNotaryImpl, multisig, sender1 } = await loadFixture(fixture)
			const tree = getNewTree()

			const secret = randomBN().toString()
			const nullifier = randomBN().toString()
			const idx = await pvtNotaryImpl.nextIndex()
			const credential = createCredential(secret, nullifier, tree, idx)

			const { proof, publicSignals } = await generateApproveSnarkProof(tree.root, sender1.address, credential)
			const { _proof, _root, _nullifierHash } = await prepareApproveCallData(proof, publicSignals)

			await pvtNotaryImpl.connect(multisig).issue(toFixedHex(credential.commitment))

			await pvtNotaryImpl.connect(sender1).approve(_proof, _root, _nullifierHash)

			const filter = pvtNotaryImpl.filters.CredentialIssued()
			const fromBlock = await ethers.provider.getBlock()
			const events = await pvtNotaryImpl.queryFilter(filter, fromBlock.number)

			expect(events).to.not.be.empty
			expect(events).to.have.length(1)
			expect(events[0].event).to.equal("CredentialIssued")
			expect(events[0].args.subject).to.equal(sender1.address)
			expect(events[0].args.nullifierHash).to.equal(_nullifierHash)
			expect(events[0].args.timestamp).to.equal(fromBlock.timestamp)

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.false
		})

		it('should detect tampering', async () => {
			const { pvtNotaryImpl, multisig, sender1, sender2 } = await loadFixture(fixture)
			const tree = getNewTree()

			const secret = randomBN().toString()
			const nullifier = randomBN().toString()
			const idx = await pvtNotaryImpl.nextIndex()
			const credential = createCredential(secret, nullifier, tree, idx)

			const { proof, publicSignals } = await generateApproveSnarkProof(tree.root, sender1.address, credential)

			const { _proof, _root, _nullifierHash } = await prepareApproveCallData(proof, publicSignals)

			await pvtNotaryImpl.connect(multisig).issue(toFixedHex(credential.commitment))

			// wrong sender
			await expect(pvtNotaryImpl.connect(sender2).approve(_proof, _root, _nullifierHash))
				.to.be.revertedWith("Invalid issuance proof")

			// wrong nullifier
			await expect(pvtNotaryImpl.connect(sender1).approve(_proof, _root, toFixedHex(0)))
				.to.be.revertedWith("Invalid issuance proof")

			// wrong proof (swaps one 1 to 0)
			await expect(pvtNotaryImpl.connect(sender1).approve(_proof.replace("1", "0"), _root, _nullifierHash)).to.be.revertedWith("Invalid issuance proof")
		})

		it('should revert if root is not known', async () => {
			const { pvtNotaryImpl, sender1 } = await loadFixture(fixture)

			const _root = toFixedHex(randomBN())
			await expect(pvtNotaryImpl.connect(sender1).approve(toFixedHex(0), _root, toFixedHex(1)))
				.to.be.revertedWith("Merkle root not found")
		})

		it('should not approve an already issued credential', async () => {
			const { pvtNotaryImpl, sender1 } = await loadFixture(fixture)

			await pvtNotaryImpl.forceApprove(toFixedHex(0), toFixedHex(1))
			await expect(pvtNotaryImpl.connect(sender1).approve(toFixedHex(0), toFixedHex(0), toFixedHex(1))).to.be.revertedWith("Credential already issued")
		})
	})

	describe('#isIssued', () => {
		it('should check whether a credential was already issued based on its nullifier hash', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)
			const _nullifierHash = toFixedHex(1)

			expect(await pvtNotaryImpl.isIssued(_nullifierHash)).to.be.false
			await pvtNotaryImpl.forceApprove(toFixedHex(0), _nullifierHash)
			expect(await pvtNotaryImpl.isIssued(_nullifierHash)).to.be.true
		})

		it('should check whether an array of credentials was already issued', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			let _nullifierHashes = []
			for (let i = 0; i < 3; i++) {
				_nullifierHashes.push(toFixedHex(i))
				await pvtNotaryImpl.forceApprove(toFixedHex(i), toFixedHex(i))
			}
			expect(await pvtNotaryImpl.isIssuedArray(_nullifierHashes)).to.has.members([true, true, true])

			expect(await pvtNotaryImpl.isIssuedArray([toFixedHex(3), toFixedHex(0), toFixedHex(1), toFixedHex(4)])).to.has.members([false, true, true, false])
		})
	})

	describe('#revoke', () => {
		it('should revoke an issued credential', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			const _nullifierHash = toFixedHex(1)
			const _reason = "some reason"
			await pvtNotaryImpl.forceApprove(toFixedHex(0), _nullifierHash)
			await pvtNotaryImpl.revoke(_nullifierHash, _reason)

			const filter = pvtNotaryImpl.filters.CredentialRevoked()
			const fromBlock = await ethers.provider.getBlock()
			const events = await pvtNotaryImpl.queryFilter(filter, fromBlock.number)

			expect(events).to.not.be.empty
			expect(events).to.have.length(1)
			expect(events[0].event).to.equal("CredentialRevoked")
			expect(events[0].args.nullifierHash).to.equal(_nullifierHash)
			expect(events[0].args.reason).to.equal(_reason)
			expect(events[0].args.timestamp).to.equal(fromBlock.timestamp)

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.true
		})

		it('should only revoke issued credentials', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			const _nullifierHash = toFixedHex(1)
			await expect(pvtNotaryImpl.revoke(_nullifierHash, "something")).to.revertedWith("Credential not found")

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.false
			expect(state.revoked).to.be.false
		})

		it('should require a reason for revocation', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			const _nullifierHash = toFixedHex(1)
			await pvtNotaryImpl.forceApprove(toFixedHex(0), _nullifierHash)
			await expect(pvtNotaryImpl.revoke(_nullifierHash, "")).to.revertedWith("A reason must be given")

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.false
		})

		it('should not revoke an already revoked credential', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			const _nullifierHash = toFixedHex(1)
			await pvtNotaryImpl.forceApprove(toFixedHex(0), _nullifierHash)
			await pvtNotaryImpl.revoke(_nullifierHash, "something")

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.true

			await expect(pvtNotaryImpl.revoke(_nullifierHash, "another thing")).to.revertedWith("Credential already revoked")
		})
	})

	describe('snark proof verification on js side', () => {
		it('should successfully verify valid issue proofs', async () => {
			let subjectWallet = ethers.Wallet.createRandom()

			const pvkDigest = createBlakeHash("blake256").update(subjectWallet.privateKey.slice(2)).digest()
			const secret = leBuff2int(pvkDigest).toString()
			const nullifier = randomBN().toString()

			let credential = { secret, nullifier }
			credential.commitment = poseidonHash2(credential.nullifier, credential.secret)
			credential.nullifierHash = poseidonHash([credential.nullifier])

			const signature = eddsa.signPoseidon(subjectWallet.privateKey, eddsa.F.e(credential.commitment))

			const publicKey = eddsa.prv2pub(subjectWallet.privateKey)
			expect(eddsa.verifyPoseidon(credential.commitment, signature, publicKey)).to.be.true

			const { proof, publicSignals } = await generateIssueSnarkProof(credential, signature, publicKey)

			expect(await plonk.verify(issueVKey, publicSignals, proof)).to.be.true
		})

		it('should successfully verify valid approval proofs', async () => {
			const { pvtNotaryImpl, sender1 } = await loadFixture(fixture)
			const tree = getNewTree()

			const secret = randomBN().toString()
			const nullifier = randomBN().toString()
			const idx = await pvtNotaryImpl.nextIndex()
			const credential = createCredential(secret, nullifier, tree, idx)

			const { proof, publicSignals } = await generateApproveSnarkProof(tree.root, sender1.address, credential)

			expect(await plonk.verify(approveVKey, publicSignals, proof)).to.be.true
		})
	})

})
