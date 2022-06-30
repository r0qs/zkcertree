// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "contracts/IssueVerifier.sol";

interface IVerifier {
    function verifyProof(bytes memory proof, uint256[] memory pubSignals) external view returns (bool);
}

contract IssuerVerifierTest is Test {
    IVerifier public verifier;
    bytes private proof;
    uint256[] private pubSignals;

    function setUp() public {
        IssueVerifier verifierContract = new IssueVerifier();
        verifier = IVerifier(address(verifierContract));
    }

    function testIssuanceProof() public {
        proof = hex"1d373171a3fa1450a1d59509a5711db2bf98920f58067708edd5aeb09a512caa1d679cc1945159baab38b69e8248b9d473b457b57eecb0c6379ea14fff4a94e72457df00e153b25cef16fbc5070a0b4642cc9212358bc9d24a41677200ab4aed2e099bc03423f7a1ce1b4d860992b8c5dbda2fcd12e62fdbc85338ff6c34625d10171c1569ee1f63a72b28198dced002d0d87cb39c1776eaae4edf63b460fbb71e8a87a0d75d40c5742564aa76c644cb570cca742b26909542a3c1461d99345d0c88c9afaaae7179afcf7e5a74f50d4b254ce48b32b9842af2e71fc1ea9ff8801ca08d6e9f5d3389f00a913c6882dc96393fd9b915c9328cba1af0c2500d9e5f0e610d7e2f7cfa0522511da9644bddce80fe217c4904bd6fba2c0bd1b0ad71651905e9c72ae22edb65a4f764ebb27bbe2329e46589aaa5ab867d3d59b267537e2efb0dccb9273c6577627e7e5e41e0e7e92544401f4da93263ab0cce400e77ed1cecd52d2fdb28d09869065a380dd570c4610e20d3298d2048b72342902d76a20dc47d9f81a431d07caa112015a73ef4c3e3aee440484a49f21f092ef801345a1a01e625242cae3178a94226194cb4675a1caa9ffc6f7a3d930664cb5984f5d51a2dd011af0cf6b4c35fa089c1fa43274257440c5a52339ede70e9e06e9fc24c0a607204b7f3900ed5881a110cfe2c8a61c53c7b3f442594daac2b113b2d96080ba49972456de94936c8e3fe558cb3acd92b2db48c0c07071cc25ea5a4275bbc0e46edf83e3aa107de6e2413c441345ed5a24d47612a7d01aec6fc5cba55695e26c2ec38e5103f0644513f37d25791167f836839640f13613bf9fc6416221b6e17e2fec50cc93abe60bf120a86c6c27739736ef54dae77b585ac2d5267533fb200e8f31d7616e5868aed4d20fd05ff039b12771e2f815fb1360582b4f1b7f00b2e365e18f39e0f17b240182af71cd35255bd0479984252f2d6079479f88c71db19bf9d17c0ed654c8e38be345bea19a7aacba38e1c36059e9d7de2a85c4a31160499c13205475d6d053cad12d2a42039b583813662b24adc35ddeb5de87836d91073264579aecbe5c97694b9163bbdfa2f1bb9ed51f1eaaaa5e7736fcb21af8c";

        uint256[4] memory signals = [
            0x0b954bd17304f2fb7134cdf4f2edfed1e8ca3988db0e609895944ff8631ff77e,
            0x2450419f296e17263e4093b813590fa10b92958d7038baaa9d94f4e631c2ee92,
            0x09e3016aecd5b55956564bd52e90dc843be52d5ec7ad51898af0388e00abd5d0,
            0x09407b5b9567846737a593ddb6eb0d0a26603fcd660c8cec88d73a24e4bf4d77
        ];

        for (uint256 i = 0; i < signals.length; i++) {
            pubSignals.push(signals[i]);
        }

        assertTrue(verifier.verifyProof(proof, pubSignals));
    }
}
