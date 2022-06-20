/* eslint-disable indent, no-undef */
require('dotenv').config()

require('@nomiclabs/hardhat-waffle')
require('@nomiclabs/hardhat-etherscan')
require("hardhat-gas-reporter")
require("solidity-coverage")

task('hasher', 'Compile Poseidon hasher', () => {
  require('./scripts/compile_hasher')
})

const chainIds = {
  goerli: 5,
  kovan: 42,
  mainnet: 1,
  rinkeby: 4,
  ropsten: 3,
  xdai: 100,
};

function getChainConfig(network, url, opts) {
  return {
    accounts: process.env.PRIVATE_KEY
      ? [process.env.PRIVATE_KEY]
      : {
        mnemonic: 'test test test test test test test test test test test junk',
        path: "m/44'/60'/0'/0",
        initialIndex: 0,
        count: 10,
      },
    chainId: chainIds[network],
    url,
    ...opts
  }
}

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
const config = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {
      // forking: {
      //   url: `https://eth-mainnet.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`,
      //   blockNumber: 14961750,
      // },
      // chainId: 1,
      initialBaseFeePerGas: 5,
      loggingEnabled: false,
      allowUnlimitedContractSize: false,
      blockGasLimit: 50000000,
    },
    localhost: {
      url: "http://localhost:8545",
      accounts: {
        mnemonic: 'test test test test test test test test test test test junk',
        path: "m/44'/60'/0'/0",
      },
    },
    mainnet: getChainConfig("mainnet", process.env.ETH_RPC || `https://eth-mainnet.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`),
    goerli: getChainConfig("goerli", `https://goerli.infura.io/v3/${process.env.INFURA_API_KEY}`),
    kovan: getChainConfig("kovan", `https://kovan.infura.io/v3/${process.env.INFURA_API_KEY}`),
    rinkeby: getChainConfig("rinkeby", `https://rinkeby.infura.io/v3/${process.env.INFURA_API_KEY}`),
    ropsten: getChainConfig("ropsten", `https://eth-ropsten.alchemyapi.io/v2/${process.env.ROPSTEN_API_KEY}`),
    xdai: getChainConfig("xdai", process.env.ETH_RPC || 'https://rpc.xdaichain.com/', { gasPrice: 25000000000 }),
  },
  solidity: {
    compilers: [
      {
        version: '0.8.13',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: "USD",
    excludeContracts: [],
    src: "./contracts",
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_KEY,
  },
  mocha: {
    timeout: 600000000,
  },
}

module.exports = config