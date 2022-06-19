// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "../Notary.sol";

contract PrivateNotaryMock is Notary {
    constructor(
        IVerifier _verifier,
        uint32 _levels,
        address _hasher,
        address _multisig
    ) Notary(_verifier, _levels, _hasher, _multisig) {
        // solhint-disable-previous-line no-empty-blocks
    }

    function forceInsert(bytes32 _leaf) public returns (uint32) {
        return _insert(_leaf);
    }

    function forceIssue(bytes32 _commitment) public {
        _insert(_commitment);
        commitments[_commitment] = true;
    }

    function forceApprove(bytes32 _commitment, bytes32 _nullifierHash) public {
        forceIssue(_commitment);
        nullifierHashes[_nullifierHash] = CredentialState(true, false);
    }

    function _processRegistration(bytes32 _commitment) internal override {
        // solhint-disable-previous-line no-empty-blocks
    }

    function _processApproval(bytes32 _nullifierHash) internal override {
        // solhint-disable-previous-line no-empty-blocks
    }

    function _processRevocation(bytes32 _nullifierHash) internal override {
        // solhint-disable-previous-line no-empty-blocks
    }
}
