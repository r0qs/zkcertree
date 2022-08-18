// SPDX-License-Identifier: GPL-3.0
// Based on TornadoCash MerkleTreeWithHistory contract
pragma solidity ^0.8.0;

interface IHasher {
    function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32);
    function poseidon(uint256[2] calldata inputs) external pure returns (uint256);
}

contract MerkleTreeWithHistory {
    uint256 public constant SCALAR_FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant ZERO_VALUE = 4480095167678736992518542286361547012092547551797443787852517300051544660649;

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
        require(uint256(_left) < SCALAR_FIELD_SIZE, "_left should be inside the field");
        require(uint256(_right) < SCALAR_FIELD_SIZE, "_right should be inside the field");
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
        if (i == 0) return bytes32(0x09e7a4dd8425015f93049a1188607ea97fbbecf09405e828177d90fe184c5aa9);
        else if (i == 1) return bytes32(0x0019ce69b31e09bcdf7aa0bec4307b923abbc84b98ab73775e4f26653f1b5936);
        else if (i == 2) return bytes32(0x29591aa91dc1ecad748a69948b2ee2bdec670627e11da243c4db6426062d701f);
        else if (i == 3) return bytes32(0x1ebdcdd8678ebf94f5627b041b5bd92276b627491afb40928cc4148a171d15f1);
        else if (i == 4) return bytes32(0x158f5b545e3d7a1507d5a043deb11e417f7530a87d810188157a97dfd4093776);
        else if (i == 5) return bytes32(0x1fcc3c909f95b672d61b9769119fecf2e132a0278b5f8764f3e2ef4e641360fe);
        else if (i == 6) return bytes32(0x092474aa5466be8d7ad1741d1289d4ae1874dc598820dd0ebbd89d749fb43260);
        else if (i == 7) return bytes32(0x07297fb5e0a9530bbbb1de755f348fef4f4bba514c9c9ee2e43cb55cf58e3085);
        else if (i == 8) return bytes32(0x13609ed431b0177184367c6722ff25aa84306d680b6b4935e542134a87d142bd);
        else if (i == 9) return bytes32(0x2c214f71681533054191538e07a2f102189602b6fe57b06e5c3872325c7247b2);
        else if (i == 10) return bytes32(0x00c4eda4fd3a09b25ffc82852b5a150a8882f1972f8f326f8beb9644397a3bd3);
        else if (i == 11) return bytes32(0x13d980abc22bdcf38901412258afe2ea9e357ea7796588386a33f7b2b9c89e91);
        else if (i == 12) return bytes32(0x0427a96ac2c931988962edf8cac479e84c4d662b324c004b1b13013069074085);
        else if (i == 13) return bytes32(0x2a95975a7e923646d27eaa3bda57aaa5234216109e18dab8dfaaff755f542cd9);
        else if (i == 14) return bytes32(0x19b6aa26b7f2a1571d32fc435aed51ca5826903f3dd8ae7571e75c95fdcf4109);
        else if (i == 15) return bytes32(0x0e3b50cffc7f3293d288687fd6188462c70b317fb7f4437f282de42e87367349);
        else if (i == 16) return bytes32(0x26c7634e2b35e5514258a4236714cd0b782e87a64d3f5160ca9ebb5ce43d7782);
        else if (i == 17) return bytes32(0x27e879285f97edb78a46acf4650e9449924a05f9194a1341728a9b9a57f0bb76);
        else if (i == 18) return bytes32(0x1e1bb08f52dc391c6519491a8f9f9c520ee5ca89aef3bdb57df18954ff4af226);
        else if (i == 19) return bytes32(0x1394e0f22efd7ccf65176fe829e40a6a6393aa0fc1b2b1adf21a00562af98db4);
        else if (i == 20) return bytes32(0x214ff1df67efa8896a55ed6d38f2cd6ca9b2da4430e8620cf26edc170a349eb4);
        else if (i == 21) return bytes32(0x1a3ac0d3a29bd8c170dc4fa8f6742da11e2e27591273c9fa50ecd15f69e51723);
        else if (i == 22) return bytes32(0x0e02185d40fb99427ad2ed2716985f76e33b9089ae9bf8f67600f72686f0b5ae);
        else if (i == 23) return bytes32(0x15978f52c75c26d974638661ddb990c620d169eac2beaf72fb945850d5aa6b7f);
        else if (i == 24) return bytes32(0x1fe35810e2bf8a2c8a553190ee7a8c70e860d0425f0dc7570435c3fb3afc4500);
        else if (i == 25) return bytes32(0x076e15a54c114d9b69297c5946885ec6f59bfb60c5154bc36428dc2151ff500f);
        else if (i == 26) return bytes32(0x09e35039dca62ed6e4dc2504a31207ec911cf8f28e8d05dcc966aae945f93155);
        else if (i == 27) return bytes32(0x15af20d07b8f632fc3acb6e46bc308bebba373f8fffa050d54ca3d425ed1e557);
        else if (i == 28) return bytes32(0x262c471a277acd4e0bda2fb32479d4f6fb4b779605aeedda5fcdf972ab15624b);
        else if (i == 29) return bytes32(0x231a17a17b2a47ee1bc7b55f3fb3cbcb846e2186d4ccac829a68916d32fbd0ba);
        else if (i == 30) return bytes32(0x193a9d89c2ecaab429c8e1bbffc750e49d36d898bbcfd88ca005367250b326e6);
        else if (i == 31) return bytes32(0x0fb65661b9fd422609254074f5781e805d143a112553631e63b6163e283a2c7b);
        else revert("Index out of bounds");
    }
}
