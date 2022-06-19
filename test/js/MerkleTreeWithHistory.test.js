const hre = require('hardhat')
const { ethers, waffle } = hre
const { loadFixture } = waffle
const { expect } = require('chai')
const { MerkleTree } = require('fixed-merkle-tree')
const { toFixedHex, deploy } = require('../../src/utils')
const Poseidon = require('../../src/poseidon')

const DEFAULT_ZERO_VALUE = 0
const MERKLE_TREE_HEIGHT = 5

describe('MerkleTreeWithHistory', function () {
  this.timeout(25000)

  before(async () => {
    poseidon = await Poseidon.initialize()
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

  function computeZeroHashes(tree_height = MERKLE_TREE_HEIGHT) {
    let zero_hashes = []
    zero_hashes[0] = 0
    for (h = 0; h < tree_height; h++) {
      zero_hashes[h + 1] = poseidonHash2(zero_hashes[h], zero_hashes[h])
    }
    return zero_hashes
  }

  async function fixture(tree_height = MERKLE_TREE_HEIGHT) {
    require('../../scripts/compile_hasher')
    const hasher = await deploy('Hasher')
    const mtContract = await deploy(
      'MerkleTreeWithHistoryMock',
      tree_height,
      hasher.address,
    )
    return {
      hasher: hasher,
      tree: mtContract
    }
  }

  describe('#constructor', () => {
    it('should correctly hash 2 leaves', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      const hashContract = await mtContract.hashLeftRight(toFixedHex(123), toFixedHex(456))
      const hash = toFixedHex(poseidon.hash([123, 456]))

      expect(hashContract).to.equal(hash)
    })

    it('should initialize', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      const zeroValue = await mtContract.ZERO_VALUE()
      const firstSubtree = await mtContract.filledSubtrees(0)
      const firstZero = await mtContract.zeros(0)

      expect(firstSubtree).to.equal(toFixedHex(zeroValue))
      expect(firstZero).to.equal(toFixedHex(zeroValue))
    })

    it('should have correct merkle root', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      const tree = getNewTree()

      expect(toFixedHex(tree.root)).to.equal(await mtContract.getLastRoot())
    })

    it('should return last root', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      await mtContract.insert(toFixedHex(123))
      await mtContract.insert(toFixedHex(456))
      const tree = getNewTree()
      tree.bulkInsert([123, 456])

      expect(await mtContract.getLastRoot()).to.equal(toFixedHex(tree.root))
    })

    it('should correctly initialize a full zeroed merkle tree', async () => {
      const { tree: mtContract } = await loadFixture(() => fixture(31))

      const zero_hashes = computeZeroHashes(32)
      for (h = 0; h < 32; h++) {
        let z = await mtContract.zeros(h)
        expect(z).to.equal(toFixedHex(zero_hashes[h]))
      }
      expect(await mtContract.getLastRoot()).to.equal(toFixedHex(zero_hashes[31]))
    })

    // it('should correctly fill a merkle tree', async () => {
    //   const { tree: mtContract } = await loadFixture(() => fixture(31))
    //   const tree = getNewTree(31)

    //   let roots = []
    //   let expectedRoots = []
    //   for (h = 0; h < 32; h++) {
    //     let e = h + 1
    //     await mtContract.insert(toFixedHex(e))
    //     expect(await mtContract.nextIndex()).to.equal(h + 1)
    //     roots.push(await mtContract.getLastRoot())

    //     tree.insert(e)
    //     expectedRoots.push(toFixedHex(tree.root))
    //   }

    //   expect(roots).to.have.members(expectedRoots)
    //   expect(await mtContract.levels()).to.equal(tree.levels)
    // })
  })

  describe('#insert', () => {
    it('should insert', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      const tree = getNewTree()

      // initial subtree should be zero
      let subtree0 = await mtContract.filledSubtrees(0)
      let subtree1 = await mtContract.filledSubtrees(1)
      expect(subtree0).to.equal(toFixedHex(DEFAULT_ZERO_VALUE))
      expect(subtree1).to.equal(toFixedHex(poseidonHash2(0, 0)))
      let nextIdx = await mtContract.nextIndex()
      expect(nextIdx).to.equal(0)

      // added leaf in the next subtree
      await mtContract.insert(toFixedHex(123))
      subtree0 = await mtContract.filledSubtrees(0)
      subtree1 = await mtContract.filledSubtrees(1)
      nextIdx = await mtContract.nextIndex()
      expect(subtree0).to.equal(toFixedHex(123))
      expect(subtree1).to.equal(toFixedHex(poseidonHash2(123, 0)))
      expect(nextIdx).to.equal(1)
      tree.insert(123)
      expect(toFixedHex(tree.root)).to.equal(await mtContract.getLastRoot())

      // subtree should only change after add arity*level number of nodes
      await mtContract.insert(toFixedHex(456))
      subtree0 = await mtContract.filledSubtrees(0)
      subtree1 = await mtContract.filledSubtrees(1)
      nextIdx = await mtContract.nextIndex()
      expect(subtree0).to.equal(toFixedHex(123))
      expect(subtree1).to.equal(toFixedHex(poseidonHash2(123, 456)))
      expect(nextIdx).to.equal(2)
      tree.insert(456)
      expect(toFixedHex(tree.root)).to.equal(await mtContract.getLastRoot())

      await mtContract.insert(toFixedHex(678))
      subtree0 = await mtContract.filledSubtrees(0)
      subtree1 = await mtContract.filledSubtrees(1)
      nextIdx = await mtContract.nextIndex()
      expect(subtree0).to.equal(toFixedHex(678))
      expect(subtree1).to.equal(toFixedHex(poseidonHash2(123, 456)))
      expect(nextIdx).to.equal(3)

      await mtContract.insert(toFixedHex(876))
      subtree0 = await mtContract.filledSubtrees(0)
      subtree1 = await mtContract.filledSubtrees(1)
      nextIdx = await mtContract.nextIndex()
      expect(subtree0).to.equal(toFixedHex(678))
      expect(subtree1).to.equal(toFixedHex(poseidonHash2(123, 456)))
      expect(nextIdx).to.equal(4)
      tree.bulkInsert([678, 876])
      expect(toFixedHex(tree.root)).to.equal(await mtContract.getLastRoot())
    })

    it('hasher gas', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      const gas = await mtContract.estimateGas.hashLeftRight(toFixedHex(123), toFixedHex(456))
      console.log('hasher gas', gas - 21000)
    })
  })

  describe('#isKnownRoot', () => {
    it('should keep history of known roots', async () => {
      const { tree: mtContract } = await loadFixture(fixture)
      const tree = getNewTree()

      for (let i = 1; i < 5; i++) {
        await mtContract.insert(toFixedHex(i))
        await tree.insert(i)
        expect(await mtContract.isKnownRoot(toFixedHex(tree.root))).to.be.true
      }
      expect(await mtContract.getLastRoot()).to.equal(toFixedHex(tree.root))

      await mtContract.insert(toFixedHex(42))
      // check outdated root
      expect(await mtContract.isKnownRoot(toFixedHex(tree.root))).to.true
    })

    it('should not return uninitialized roots', async () => {
      const { tree: mtContract } = await loadFixture(fixture)

      await mtContract.insert(toFixedHex(42))
      expect(await mtContract.isKnownRoot(toFixedHex(0))).to.be.false
    })
  })
})