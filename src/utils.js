/* Based on: https://github.com/tornadocash/tornado-nova/blob/master/src/utils.js */
const crypto = require('crypto')
const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { MerkleTree } = require('fixed-merkle-tree')
const { plonk } = require('snarkjs')
const { unstringifyBigInts } = require('ffjavascript').utils

// TODO: load from config
const MERKLE_TREE_HEIGHT = process.env.MERKLE_TREE_HEIGHT || 12
const ZERO_VALUE = process.env.ZERO_VALUE || 0
const FIELD_SIZE = BigNumber.from(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
)

const randomBN = (length = 32) => BigNumber.from(crypto.randomBytes(length))

// BigNumber to hex string of specified length
const toFixedHex = (number, length = 32) => {
  const str = number instanceof Buffer ? number.toString('hex') : BigNumber.from(number).toHexString().replace('0x', '')
  return '0x' + str.padStart(length * 2, '0')
}

// Convert bigint value into buffer of specified byte length
const toBuffer = (value, length) =>
  Buffer.from(
    BigNumber.from(value)
      .toHexString()
      .slice(2)
      .padStart(length * 2, '0'),
    'hex',
  )

async function deploy(contractName, ...args) {
  const Factory = await ethers.getContractFactory(contractName)
  const instance = await Factory.deploy(...args) // TODO: connect(sender)
  return instance.deployed()
}

// Builds a local merkle tree based on notary events
async function buildMerkleTree(notary, hashfn, tree_height = MERKLE_TREE_HEIGHT, zero = ZERO_VALUE) {
  const filter = notary.filters.CredentialCreated()
  const events = await notary.queryFilter(filter, 0)

  const leaves = events.sort((a, b) => a.args.index - b.args.index).map((e) => BigNumber.from(e.args.commitment).toString())

  return new MerkleTree(tree_height, leaves, { hashFunction: hashfn, zeroElement: zero })
}

// Compute merkle proof of the commitment with on-chain data
async function generateMerkleProof(notary, hashfn, commitment) {
  const tree = await buildMerkleTree(notary, hashfn)

  const index = tree.indexOf(commitment)
  const { pathElements, pathIndices } = tree.path(index)

  return { pathElements, pathIndices, root: tree.root }
}

async function prepareSolidityCallData(proofData, publicSignals) {
  const calldata = await plonk.exportSolidityCallData(unstringifyBigInts(proofData), unstringifyBigInts(publicSignals))
  const [proof, ...rest] = calldata.split(",")

  return {
    proof: proof,
    publicSignals: JSON.parse(rest.join(","))
  }
}

// Converts a bit array to decimal
function bitArrayToDecimal(array) {
  // TODO: ensure that array contains only 0 or 1
  return parseInt(array.reverse().join(""), 2)
}

module.exports = {
  MERKLE_TREE_HEIGHT,
  FIELD_SIZE,
  randomBN,
  toFixedHex,
  toBuffer,
  deploy,
  buildMerkleTree,
  generateMerkleProof,
  prepareSolidityCallData,
  bitArrayToDecimal
}