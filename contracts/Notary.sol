// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import "contracts/MerkleTreeWithHistory.sol";

interface IVerifier {
    function verifyProof(bytes memory proof, uint256[] memory pubSignals) external view returns (bool);
}

abstract contract Notary is MerkleTreeWithHistory {
    struct CredentialState {
        bool issued;
        bool revoked;
        uint256 expirationDate; //TODO
    }

    IVerifier public immutable verifier;
    address public immutable multisig;
    bytes32 public root; // TODO: keep history of last 10 roots
    mapping(bytes32 => CredentialState) public nullifierHashes;
    // kept to prevent accidental issuance with the same commitment
    mapping(bytes32 => bool) public commitments; // FIXME: maybe not really needed (remove)

    event CredentialCreated(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event CredentialIssued(address indexed subject, bytes32 nullifierHash, uint256 timestamp);
    event CredentialRevoked(bytes32 indexed nullifierHash, string reason, uint256 timestamp);

    modifier onlyMultisig() {
        require(msg.sender == multisig, "only multisig");
        _;
    }

    /**
     * @dev The constructor
     * @param _verifier the address of SNARK verifier for this contract
     * @param _levels hight of the commitments merkle tree
     * @param _hasher hasher address for the merkle tree
     * @param _multisig multisig contract address
     */
    constructor(
        IVerifier _verifier,
        uint32 _levels,
        address _hasher,
        address _multisig
    ) MerkleTreeWithHistory(_levels, _hasher) {
        verifier = _verifier;
        multisig = _multisig;
    }

    /**
     * @dev Registers a credential into the contract.
     * @param _commitment the credential commitment of a subject, which is
     * Poseidon(nullifier + secret)
     */
    function issue(bytes32 _commitment) public onlyMultisig {
        require(!commitments[_commitment], "Commitment already registered");

        uint32 insertedIndex = _insert(_commitment);
        commitments[_commitment] = true;
        _processRegistration(_commitment);

        // solhint-disable-next-line not-rely-on-time
        emit CredentialCreated(_commitment, insertedIndex, block.timestamp);
    }

    /**
     * @dev this function is defined in a child contract
     */
    function _processRegistration(bytes32 _commitment) internal virtual;

    /**
     * @dev Approves the issuance of a registered credential.
     * @param _proof a zkSNARK proof data generated by the approval circuit
     * @param _root the merkle root of all credentials in the contract
     * @param _nullifierHash the hash of unique credential nullifier
     */
    function approve(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash
    ) public {
        require(!isIssued(_nullifierHash), "Credential already issued");
        require(isKnownRoot(_root), "Cannot find the merkle root");

        uint256[] memory pubSignals = new uint256[](3);
        pubSignals[0] = uint256(_root);
        pubSignals[1] = uint256(_nullifierHash);
        pubSignals[2] = uint256(uint160(msg.sender));
        require(verifier.verifyProof(_proof, pubSignals), "Invalid issuance proof");

        nullifierHashes[_nullifierHash] = CredentialState(true, false, 0);
        _processApproval(_nullifierHash);

        // solhint-disable-next-line not-rely-on-time
        emit CredentialIssued(msg.sender, _nullifierHash, block.timestamp);
    }

    /**
     * @dev this function is defined in a child contract
     */
    function _processApproval(bytes32 _nullifierHash) internal virtual;

    /**
     * @dev Revokes a credential.
     * @param _nullifierHash the hash of unique credential nullifier
     * @param _reason summary of the reason for revocation
     */
    function revoke(bytes32 _nullifierHash, string memory _reason) public onlyMultisig {
        require(isIssued(_nullifierHash), "Credential not found");
        require(!isRevoked(_nullifierHash), "Credential already revoked");

        _processRevocation(_nullifierHash);

        // solhint-disable-next-line not-rely-on-time
        emit CredentialRevoked(_nullifierHash, _reason, block.timestamp);
    }

    /**
     * @dev this function is defined in a child contract
     */
    function _processRevocation(bytes32 _nullifierHash) internal virtual;

    /**
     * @dev whether a credential is revoked
     */
    function isRevoked(bytes32 _nullifierHash) public view returns (bool) {
        return nullifierHashes[_nullifierHash].revoked;
    }

    /**
     * @dev whether a credential is already issued
     */
    function isIssued(bytes32 _nullifierHash) public view returns (bool) {
        return nullifierHashes[_nullifierHash].issued;
    }

    /**
     * @dev whether an array of credential is already issued
     */
    function isIssuedArray(bytes32[] calldata _nullifierHashes) external view returns (bool[] memory issued) {
        issued = new bool[](_nullifierHashes.length);
        for (uint256 i = 0; i < _nullifierHashes.length; i++) {
            if (isIssued(_nullifierHashes[i])) {
                issued[i] = true;
            }
        }
    }
}

contract PrivateNotary is Notary {
    constructor(
        IVerifier _verifier,
        uint32 _levels,
        address _hasher,
        address _multisig
    ) Notary(_verifier, _levels, _hasher, _multisig) {
        // solhint-disable-previous-line no-empty-blocks
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
