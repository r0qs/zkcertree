const crypto = require('crypto')
const { BigNumber } = require('hardhat').ethers

const randomBN = (length = 32) => BigNumber.from(crypto.randomBytes(length))

module.exports = { randomBN }