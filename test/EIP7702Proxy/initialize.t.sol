// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {CoinbaseSmartWallet} from "../../lib/smart-wallet/src/CoinbaseSmartWallet.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ERC1967Utils} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol";

contract InitializeTest is EIP7702ProxyBase {
    function testSucceedsWithValidSignature() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        // Verify initialization through implementation at the EOA's address
        CoinbaseSmartWallet wallet = CoinbaseSmartWallet(payable(_eoa));
        assertTrue(
            wallet.isOwnerAddress(_newOwner),
            "New owner should be owner after initialization"
        );
    }

    function testRevertsWithInvalidSignature() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = hex"deadbeef"; // Invalid signature

        vm.expectRevert(); // Should revert with signature verification error
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function testRevertsWithWrongSigner() public {
        // Create signature with different private key
        uint256 wrongPk = 0xC0FFEE; // Using a different key than either EOA or new owner

        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes32 initHash = keccak256(abi.encode(_eoa, initArgs));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, initHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(); // Should revert with signature verification error
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function testCanOnlyBeCalledOnce() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        // Try to initialize again
        vm.expectRevert(CoinbaseSmartWallet.Initialized.selector);
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
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
}
