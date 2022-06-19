// SPDX-License-Identifier: GPL-3.0
// Based on TornadoCash MerkleTreeWithHistory contract
pragma solidity ^0.8.0;

interface IHasher {
    function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32);
    function poseidon(uint256[2] calldata inputs) external pure returns (uint256);
}

contract MerkleTreeWithHistory {
    uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant ZERO_VALUE = 0;

    IHasher public immutable hasher;
    uint32 public immutable levels;

    mapping(uint256 => bytes32) public filledSubtrees;
    mapping(uint256 => bytes32) public roots;
    uint32 public constant ROOT_HISTORY_SIZE = 100;
    uint32 public currentRootIndex = 0;
    uint32 public nextIndex = 0;

    constructor(uint32 _levels, address _hasher) {
        require(_levels > 0, "_levels should be greater than 0");
        require(_levels < 32, "_levels should be less than 32");
        levels = _levels;
        hasher = IHasher(_hasher);

        // Initialize subtrees with zero hashed values
        for (uint32 i = 0; i < levels; i++) {
            filledSubtrees[i] = zeros(i);
        }
        roots[0] = zeros(levels);
    }

    /**
     * @dev Hash 2 tree leaves
     * @return Poseidon(_left, _right)
     */
    function hashLeftRight(bytes32 _left, bytes32 _right) public view returns (bytes32) {
        require(uint256(_left) < FIELD_SIZE, "_left should be inside the field");
        require(uint256(_right) < FIELD_SIZE, "_right should be inside the field");
        bytes32[2] memory input;
        input[0] = _left;
        input[1] = _right;
        return hasher.poseidon(input);
    }

    /**
     * @dev Inserts a leaf into the left-most available position in the Merkle Tree
     * @return index of the next available position
     */
    function _insert(bytes32 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        require(_nextIndex != uint32(2)**levels, "Merkle tree is full.");
        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = _leaf;
        bytes32 left;
        bytes32 right;

        for (uint32 i = 0; i < levels; i++) {
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = zeros(i);
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = hashLeftRight(left, right);
            currentIndex /= 2;
        }

        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    /**
     * @dev Whether the root is present in the root history
     */
    function isKnownRoot(bytes32 _root) public view returns (bool) {
        if (_root == 0) {
            return false;
        }
        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        do {
            if (_root == roots[i]) {
                return true;
            }
            if (i == 0) {
                i = ROOT_HISTORY_SIZE;
            }
            i--;
        } while (i != _currentRootIndex);
        return false;
    }

    /**
     * @dev Returns the last root
     */
    function getLastRoot() public view returns (bytes32) {
        return roots[currentRootIndex];
    }

    /**
     * @dev provides Zero (Empty) elements for a Poseidon MerkleTree. Up to 32 levels
     */
    function zeros(uint256 i) public pure returns (bytes32) {
        if (i == 0) return bytes32(ZERO_VALUE);
        else if (i == 1) return bytes32(0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864);
        else if (i == 2) return bytes32(0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1);
        else if (i == 3) return bytes32(0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238);
        else if (i == 4) return bytes32(0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a);
        else if (i == 5) return bytes32(0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55);
        else if (i == 6) return bytes32(0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78);
        else if (i == 7) return bytes32(0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d);
        else if (i == 8) return bytes32(0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61);
        else if (i == 9) return bytes32(0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747);
        else if (i == 10) return bytes32(0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2);
        else if (i == 11) return bytes32(0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636);
        else if (i == 12) return bytes32(0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a);
        else if (i == 13) return bytes32(0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0);
        else if (i == 14) return bytes32(0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c);
        else if (i == 15) return bytes32(0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92);
        else if (i == 16) return bytes32(0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323);
        else if (i == 17) return bytes32(0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992);
        else if (i == 18) return bytes32(0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f);
        else if (i == 19) return bytes32(0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca);
        else if (i == 20) return bytes32(0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e);
        else if (i == 21) return bytes32(0x19df90ec844ebc4ffeebd866f33859b0c051d8c958ee3aa88f8f8df3db91a5b1);
        else if (i == 22) return bytes32(0x18cca2a66b5c0787981e69aefd84852d74af0e93ef4912b4648c05f722efe52b);
        else if (i == 23) return bytes32(0x2388909415230d1b4d1304d2d54f473a628338f2efad83fadf05644549d2538d);
        else if (i == 24) return bytes32(0x27171fb4a97b6cc0e9e8f543b5294de866a2af2c9c8d0b1d96e673e4529ed540);
        else if (i == 25) return bytes32(0x2ff6650540f629fd5711a0bc74fc0d28dcb230b9392583e5f8d59696dde6ae21);
        else if (i == 26) return bytes32(0x120c58f143d491e95902f7f5277778a2e0ad5168f6add75669932630ce611518);
        else if (i == 27) return bytes32(0x1f21feb70d3f21b07bf853d5e5db03071ec495a0a565a21da2d665d279483795);
        else if (i == 28) return bytes32(0x24be905fa71335e14c638cc0f66a8623a826e768068a9e968bb1a1dde18a72d2);
        else if (i == 29) return bytes32(0x0f8666b62ed17491c50ceadead57d4cd597ef3821d65c328744c74e553dac26d);
        else if (i == 30) return bytes32(0x0918d46bf52d98b034413f4a1a1c41594e7a7a3f6ae08cb43d1a2a230e1959ef);
        else if (i == 31) return bytes32(0x1bbeb01b4c479ecde76917645e404dfa2e26f90d0afc5a65128513ad375c5ff2);
        else revert("Index out of bounds");
    }
}
