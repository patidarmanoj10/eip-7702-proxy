// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {MockImplementation} from "../mocks/MockImplementation.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract InitializeTest is EIP7702ProxyBase {
    function testSucceedsWithValidSignature() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        // Verify implementation was set
        assertEq(
            _getERC1967Implementation(address(_eoa)),
            address(_implementation),
            "Implementation should be set after initialization"
        );
    }

    function testSetsERC1967ImplementationSlot() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        address storedImpl = _getERC1967Implementation(address(_eoa));
        assertEq(
            storedImpl,
            address(_implementation),
            "ERC1967 implementation slot should store implementation address"
        );
    }

    function testEmitsUpgradedEvent() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        vm.expectEmit(true, false, false, false, address(_eoa));
        emit EIP7702Proxy.Upgraded(address(_implementation));
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function testRevertsWithInvalidSignatureLength() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = hex"deadbeef"; // Too short to be valid ECDSA signature

        vm.expectRevert(
            abi.encodeWithSignature("ECDSAInvalidSignatureLength(uint256)", 4)
        );
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function testRevertsWithInvalidSignature() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        // 65 bytes of invalid signature data
        bytes memory signature = new bytes(65);

        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function testRevertsWithWrongSigner() public {
        uint256 wrongPk = 0xC0FFEE;
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes32 initHash = keccak256(abi.encode(_eoa, initArgs));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, initHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }
}
