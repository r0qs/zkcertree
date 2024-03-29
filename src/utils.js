/* Based on: https://github.com/tornadocash/tornado-nova/blob/master/src/utils.js */
const crypto = require('crypto')
const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { MerkleTree } = require('fixed-merkle-tree')
const { DocumentTree } = require('document-tree')
const { plonk } = require('snarkjs')
const { unstringifyBigInts } = require('ffjavascript').utils

// TODO: load from config
const MERKLE_TREE_HEIGHT = process.env.MERKLE_TREE_HEIGHT || 12
const SCALAR_FIELD_SIZE = BigNumber.from(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
)
const ZERO_VALUE = process.env.ZERO_VALUE || zeroValue("zkcertree")

const randomBN = (length = 32) => BigNumber.from(crypto.randomBytes(length))

function randomDoc(issuer, subject, period = 0) {
  return {
    grade: Math.floor(Math.random() * 100),
    tag: Math.random().toString(16).substring(2, 8),
    subject: subject,
    issuer: issuer,
    reference: toFixedHex(randomBN()), // storage chunk reference
    timestamp: setDate(period).getTime() // in millisecond
  }
}

// BigNumber to hex string of specified length
function toFixedHex(number, length = 32) {
  const str = number instanceof Buffer ? number.toString('hex') : BigNumber.from(number).toHexString().replace('0x', '')
  return '0x' + str.padStart(length * 2, '0')
}

// Convert bigint value into buffer of specified byte length
function toBuffer(value, length) {
  Buffer.from(
    BigNumber.from(value)
      .toHexString()
      .slice(2)
      .padStart(length * 2, '0'),
    'hex',
  )
}

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
  const { pathElements, pathIndices } = tree.proof(commitment)

  return { pathElements, pathIndices, root: tree.root }
}

async function generateMerkleMultiProof(notary, hashfn, commitments) {
  const tree = await buildMerkleTree(notary, hashfn)
  const { pathElements, leafIndices } = tree.multiProof(commitments)

  return { pathElements, leafIndices, root: tree.root }
}

async function prepareSolidityCallData(proofData, publicSignals) {
  const calldata = await plonk.exportSolidityCallData(unstringifyBigInts(proofData), unstringifyBigInts(publicSignals))
  const [proof, ...rest] = calldata.split(",")

  return {
    proof: proof,
    publicSignals: JSON.parse(rest.join(","))
  }
}

function prepareCertreeProofInputs(certree, credentials) {
  const certProofs = []
  for (let i = 0; i < credentials.length; i++) {
    let p = certree.proof(credentials[i].commitment)
    certProofs[i] = {
      pathCertreeElements: [...p.pathElements],
      pathCertreeIndices: bitArrayToDecimal(p.pathIndices).toString()
    }
  }
  return certProofs
}

function createDocumentTree(document, hashFunction, leafHashFunction) {
  let doctree = new DocumentTree({
    zero: ZERO_VALUE,
    hashFunction: hashFunction,
    leafHashFunction: leafHashFunction
  })
  doctree.addLeavesFromDocument(document)
  return doctree
}

function generateDocuments(n, issuer, subject, hashFunction, leafHashFunction) {
  let docs = []
  for (let i = 0; i < n; i++) {
    docs.push(createDocumentTree(randomDoc(issuer, subject, i*10), hashFunction, leafHashFunction))
  }
  return docs
}

// Converts a bit array to decimal
function bitArrayToDecimal(array) {
  const arr = [...array]
  // TODO: ensure that array contains only 0 or 1
  return parseInt(arr.reverse().join(""), 2)
}

function bufferToBigIntField(buf) {
  let n = BigNumber.from(buf)
  if (n > SCALAR_FIELD_SIZE) {
    n = n.mod(SCALAR_FIELD_SIZE);
  }
  return n.toBigInt()
}

// Returns the zero value of the form: keccak256(string_value) % SCALAR_FIELD_SIZE
function zeroValue(input) {
  const abi = new ethers.utils.AbiCoder()
  const encodedData = abi.encode(["string"], [input])
  const hash = ethers.utils.keccak256(encodedData)
  return BigNumber.from(hash).mod(SCALAR_FIELD_SIZE).toString()
}

function setDate(period) {
  let date = new Date()
  date.setDate(date.getDate() + period)
  return date
}

function weightedSum(elements, weights) {
  return elements.reduce((sum, e, i) => {
    sum += e * weights[i]
    return sum
  }, 0)
}

module.exports = {
  ZERO_VALUE,
  MERKLE_TREE_HEIGHT,
  SCALAR_FIELD_SIZE,
  randomBN,
  toFixedHex,
  toBuffer,
  bufferToBigIntField,
  deploy,
  buildMerkleTree,
  prepareCertreeProofInputs,
  generateDocuments,
  generateMerkleProof,
  generateMerkleMultiProof,
  prepareSolidityCallData,
  bitArrayToDecimal,
  weightedSum
}
