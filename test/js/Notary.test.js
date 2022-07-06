const hre = require('hardhat')
const { ethers, waffle } = hre
const { loadFixture } = waffle
const { utils } = ethers
const { expect } = require('chai')
const { plonk } = require('snarkjs')
const { buildEddsa } = require('circomlibjs')
const { MerkleTree } = require('fixed-merkle-tree')
const {
	FIELD_SIZE,
	deploy,
	randomBN,
	toFixedHex } = require('../../src/utils')
const Poseidon = require('../../src/poseidon')
const IssueProver = require('../../src/issue')
const ApproveProver = require('../../src/approve')

const ZERO_VALUE = 0
const MERKLE_TREE_HEIGHT = 12

describe('PrivateNotary', function () {

	before(async () => {
		eddsa = await buildEddsa()
		poseidon = await Poseidon.initialize()
		issueProver = await IssueProver.initialize()
		approveProver = await ApproveProver.initialize()
	})

	function poseidonHash(items) {
		return poseidon.hash(items)
	}

	function poseidonHash2(a, b) {
		return poseidonHash([a, b])
	}

	function getNewTree(leaves = [], tree_height = MERKLE_TREE_HEIGHT, zero = ZERO_VALUE) {
		return new MerkleTree(tree_height, leaves, { hashFunction: poseidonHash2, zeroElement: zero })
	}

	function createCredential(secret, publicKey, root) {
		let credential = { secret, root }
		credential.subject = poseidonHash2(eddsa.F.toObject(publicKey[0]), eddsa.F.toObject(publicKey[1]))
		credential.commitment = poseidonHash([credential.root, credential.subject, credential.secret])
		credential.nullifierHash = poseidonHash([credential.root])
		return credential
	}

	// insertCommitment inserts a commitment in the tree and returns the merkle proof
	function insertCommitment(tree, commitment) {
		tree.insert(commitment)

		const index = tree.indexOf(commitment)
		const { pathElements, pathIndices } = tree.path(index)

		return { pathElements, pathIndices, root: tree.root }
	}

	function getAccountConfig() {
		const networkConfig = hre.config.networks[hre.config.defaultNetwork]
		return {
			mnemonic: networkConfig.accounts.mnemonic,
			path: networkConfig.accounts.path
		}
	}

	function getWallet(idx) {
		const accountConfig = getAccountConfig()
		const accountPath = accountConfig.path.concat(`/${idx}`)
		return utils.HDNode.fromMnemonic(accountConfig.mnemonic).derivePath(accountPath)
	}

	async function fixture(tree_height = MERKLE_TREE_HEIGHT) {
		require('../../scripts/compile_hasher')

		const [multisig, sender1, sender2] = await ethers.getSigners()
		const approveVerifier = await deploy('Approve12Verifier')
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
			expect(await pvtNotaryImpl.ZERO_VALUE()).to.equal(ZERO_VALUE)
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
			const commitment1 = toFixedHex(42)
			const commitment2 = toFixedHex(43)

			let block = await ethers.provider.getBlock()
			expect(await pvtNotaryImpl.connect(multisig).issue(commitment1))
				.to.emit(pvtNotaryImpl, "CredentialCreated")
				.withArgs(commitment1, 0, block.timestamp)

			block = await ethers.provider.getBlock()
			expect(await pvtNotaryImpl.connect(multisig).issue(commitment2))
				.to.emit(pvtNotaryImpl, "CredentialCreated")
				.withArgs(commitment2, 1, block.timestamp)
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
			const credentialRoot = randomBN().toString()

			const wallet = getWallet(1) // sender1
			const publicKey = eddsa.prv2pub(wallet.privateKey)
			const credential = createCredential(secret, publicKey, credentialRoot)
			const merkleProof = insertCommitment(tree, credential.commitment)

			const { proof, publicSignals } = await approveProver.generateSnarkProof(merkleProof, sender1.address, credential)
			const { _proof, _root, _nullifierHash } = await approveProver.prepareCallData(proof, publicSignals)

			await pvtNotaryImpl.connect(multisig).issue(toFixedHex(credential.commitment))

			const fromBlock = await ethers.provider.getBlock()
			expect(await pvtNotaryImpl.connect(sender1).approve(_proof, _root, _nullifierHash))
				.to.emit(pvtNotaryImpl, "CredentialIssued")
				.withArgs(sender1.address, _nullifierHash, fromBlock.timestamp)

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.false
		})

		it('should detect tampering', async () => {
			const { pvtNotaryImpl, multisig, sender1, sender2 } = await loadFixture(fixture)
			const tree = getNewTree()

			const secret = randomBN().toString()
			const credentialRoot = randomBN().toString()

			const wallet = getWallet(1) // sender1
			const publicKey = eddsa.prv2pub(wallet.privateKey)
			const credential = createCredential(secret, publicKey, credentialRoot)
			const merkleProof = insertCommitment(tree, credential.commitment)

			const { proof, publicSignals } = await approveProver.generateSnarkProof(merkleProof, sender1.address, credential)

			const { _proof, _root, _nullifierHash } = await approveProver.prepareCallData(proof, publicSignals)

			await pvtNotaryImpl.connect(multisig).issue(toFixedHex(credential.commitment))

			// wrong subject
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

		it('should approve using the latest root on-chain', async () => {
			const { pvtNotaryImpl, multisig, sender1 } = await loadFixture(fixture)
			const wallet = getWallet(1) // sender1
			const publicKey = eddsa.prv2pub(wallet.privateKey)

			// creates 3 commitments
			let credential
			for (let i = 0; i < 3; i++) {
				let secret = randomBN().toString()
				let credentialRoot = randomBN().toString()
				let cred = createCredential(secret, publicKey, credentialRoot)

				// save the first credential to test
				if (i == 0) {
					credential = cred
				}

				await pvtNotaryImpl.connect(multisig).issue(toFixedHex(cred.commitment))
			}

			let { proof, publicSignals } = await approveProver.generateSnarkProofFromContract(pvtNotaryImpl, poseidonHash2, sender1.address, credential)

			let { _proof, _root, _nullifierHash } = await approveProver.prepareCallData(proof, publicSignals)

			const fromBlock = await ethers.provider.getBlock()
			expect(await pvtNotaryImpl.connect(sender1).approve(_proof, _root, _nullifierHash))
				.to.emit(pvtNotaryImpl, "CredentialIssued")
				.withArgs(sender1.adress, _nullifierHash, fromBlock.timestamp)

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.false
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

			const fromBlock = await ethers.provider.getBlock()
			expect(await pvtNotaryImpl.revoke(_nullifierHash, _reason))
				.to.emit(pvtNotaryImpl, "CredentialRevoked")
				.withArgs(_nullifierHash, _reason, fromBlock.timestamp)

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.true
			expect(state.revoked).to.be.true
		})

		it('should only revoke issued credentials', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			const _nullifierHash = toFixedHex(1)
			await expect(pvtNotaryImpl.revoke(_nullifierHash, "something"))
				.to.be.revertedWith("Credential not found")

			const state = await pvtNotaryImpl.nullifierHashes(_nullifierHash)
			expect(state.issued).to.be.false
			expect(state.revoked).to.be.false
		})

		it('should require a reason for revocation', async () => {
			const { pvtNotaryImpl } = await loadFixture(fixture)

			const _nullifierHash = toFixedHex(1)
			await pvtNotaryImpl.forceApprove(toFixedHex(0), _nullifierHash)
			await expect(pvtNotaryImpl.revoke(_nullifierHash, ""))
				.to.be.revertedWith("A reason must be given")

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

			await expect(pvtNotaryImpl.revoke(_nullifierHash, "another thing"))
				.to.be.revertedWith("Credential already revoked")
		})
	})

	describe('snark proof verification on js side', () => {
		it('should successfully verify valid issue proofs', async () => {
			const secret = randomBN().toString()
			const credentialRoot = randomBN().toString()
			const wallet = ethers.Wallet.createRandom()
			const publicKey = eddsa.prv2pub(wallet.privateKey)
			const credential = createCredential(secret, publicKey, credentialRoot)

			const signature = eddsa.signPoseidon(wallet.privateKey, eddsa.F.e(credential.commitment))

			expect(eddsa.verifyPoseidon(credential.commitment, signature, publicKey)).to.be.true

			const { proof, publicSignals } = await issueProver.generateSnarkProof(credential, signature, publicKey)

			expect(await plonk.verify(issueProver.verificationKey(), publicSignals, proof)).to.be.true
		})

		it('should successfully verify valid approval proofs', async () => {
			const secret = randomBN().toString()
			const credentialRoot = randomBN().toString()
			const wallet = ethers.Wallet.createRandom()
			const publicKey = eddsa.prv2pub(wallet.privateKey)
			const credential = createCredential(secret, publicKey, credentialRoot)

			const tree = getNewTree()
			const merkleProof = insertCommitment(tree, credential.commitment)

			const { proof, publicSignals } = await approveProver.generateSnarkProof(merkleProof, wallet.address, credential)

			expect(await plonk.verify(approveProver.verificationKey(), publicSignals, proof)).to.be.true
		})
	})

})
