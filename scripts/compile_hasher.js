// Modified from: https://github.com/tornadocash/tornado-nova/blob/master/scripts/compileHasher.js

// Generates Hasher artifact at compile-time
const path = require('path')
const fs = require('fs')
const { createCode, generateABI } = require('circomlibjs').poseidonContract;
const outputPath = path.join(__dirname, '..', 'artifacts', 'contracts', 'Hasher.sol')
const outputFile = path.join(outputPath, 'Hasher.json')

if (!fs.existsSync(outputPath)) {
  fs.mkdirSync(outputPath, { recursive: true })
}

const contract = {
  _format: 'hh-sol-artifact-1',
  sourceName: 'contracts/Hasher.sol',
  linkReferences: {},
  deployedLinkReferences: {},
  contractName: 'Hasher',
  abi: generateABI(2),
  bytecode: createCode(2),
  deployedBytecode: ""
}

fs.writeFileSync(outputFile, JSON.stringify(contract, null, 2))