// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "../MerkleTree.sol";

contract MerkleTreeMock is MerkleTree {
  constructor(uint32 _treeLevels, address _hasher) MerkleTree(_treeLevels, _hasher) {
    // solhint-disable-previous-line no-empty-blocks
  }

  function insert(bytes32 _leaf) public returns (uint32) {
    return _insert(_leaf);
  }
}