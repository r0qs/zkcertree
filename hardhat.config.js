/* eslint-disable indent, no-undef */
require('dotenv').config()

const fs = require('fs')
require('@nomiclabs/hardhat-waffle')
require('@nomiclabs/hardhat-etherscan')
require('hardhat-preprocessor')
require('hardhat-gas-reporter')
require('solidity-coverage')

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
  fuji: 43113,
  avalanche: 43114,
  mumbai: 80001
};

function getChainConfig(network, url, opts) {
  return {
    accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : {
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

// https://book.getfoundry.sh/config/hardhat.html
function getRemappings() {
  return fs
  .readFileSync("remappings.txt", "utf8")
  .split("\n")
  .filter((line) => !!line) // ignore null and undefined values
  .map((line) => line.trim().split("="))
}

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
const config = {
  defaultNetwork: 'hardhat',
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
      url: 'http://localhost:8545',
      accounts: {
        mnemonic: 'test test test test test test test test test test test junk',
        path: "m/44'/60'/0'/0",
      },
    },
    mainnet: getChainConfig('mainnet', process.env.ETH_RPC || `https://eth-mainnet.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`),
    goerli: getChainConfig('goerli', `https://goerli.infura.io/v3/${process.env.INFURA_API_KEY}`),
    kovan: getChainConfig('kovan', `https://kovan.infura.io/v3/${process.env.INFURA_API_KEY}`),
    rinkeby: getChainConfig('rinkeby', `https://rinkeby.infura.io/v3/${process.env.INFURA_API_KEY}`),
    ropsten: getChainConfig('ropsten', `https://eth-ropsten.alchemyapi.io/v2/${process.env.ROPSTEN_API_KEY}`),
    xdai: getChainConfig('xdai', 'https://rpc.xdaichain.com/', { gasPrice: 25000000000 }),
    fuji: getChainConfig('fuji', 'https://api.avax-test.network/ext/bc/C/rpc', { gasPrice: 225000000000 }),
    avalanche: getChainConfig('avalanche', 'https://api.avax.network/ext/bc/C/rpc', { gasPrice: 225000000000 }),
    avaxLocal: {
      url: 'http://localhost:9650/ext/bc/C/rpc',
      gasPrice: 225000000000,
      chainId: 43112,
    },
    mumbai: getChainConfig('mumbai', 'https://rpc-mumbai.maticvigil.com')
  },
  // https://docs.soliditylang.org/en/v0.8.15/using-the-compiler.html?highlight=evmVersion#target-options
  solidity: {
    compilers: [
      {
        version: '0.8.13',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          outputSelection: {
            "*": {
              "*": [
                "metadata",
                "abi",
                "evm.bytecode.object",
                "evm.bytecode.sourceMap",
                "evm.deployedBytecode.object",
                "evm.deployedBytecode.sourceMap"
              ],
              "": ["ast"]
            }
          },
          evmVersion: "london"
        },
      },
    ],
  },
  paths: {
    sources: "./contracts",
    cache: "./hardhat-cache",
    tests: "./test/js",
    artifacts: "./artifacts/hardhat"
  },
  // This fully resolves paths for imports in the ./lib directory for Hardhat
  preprocess: {
    eachLine: (hre) => ({
      transform: (line) => {
        if (line.match(/^\s*import /i)) {
          getRemappings().forEach(([find, replace]) => {
            if (line.match(find)) {
              line = line.replace(find, replace);
            }
          });
        }
        return line;
      },
    }),
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: "USD",
    excludeContracts: [],
    src: "contracts",
    showTimeSpent: true,
    showMethodSig: true,
    onlyCalledMethods: true,
    coinmarketcap: process.env.COINMARKETCAP_APIKEY !== undefined
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_KEY,
  },
  mocha: {
    timeout: 600000000,
  },
}

module.exports = config