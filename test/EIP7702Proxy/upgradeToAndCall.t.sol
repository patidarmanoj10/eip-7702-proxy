// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {CoinbaseSmartWallet} from "../../lib/smart-wallet/src/CoinbaseSmartWallet.sol";
import {UUPSUpgradeable} from "solady/src/utils/UUPSUpgradeable.sol";

contract UpgradeToAndCallTest is EIP7702ProxyBase {
    DummyImplementation newImplementation;

    function setUp() public override {
        super.setUp();

        // Initialize the proxy first
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);
        vm.prank(_eoa);
        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        // Deploy new implementation
        newImplementation = new DummyImplementation();
    }

    function testUpgradeToAndCall() public {
        // Only owner should be able to upgrade
        vm.prank(_newOwner);

        CoinbaseSmartWallet(payable(_eoa)).upgradeToAndCall(
            address(newImplementation),
            abi.encodeWithSignature("dummy()")
        );

        // Verify upgrade worked by calling new function
        vm.expectEmit(true, true, true, true, _eoa);
        emit DummyImplementation.DummyCalled();
        DummyImplementation(payable(_eoa)).dummy();
    }

    function testUpgradeToAndCallRevertsForNonOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(); // CoinbaseSmartWallet will revert for non-owner
        CoinbaseSmartWallet(payable(_eoa)).upgradeToAndCall(
            address(newImplementation),
            ""
        );
    }
}

contract DummyImplementation is UUPSUpgradeable {
    event DummyCalled();

    function dummy() external {
        emit DummyCalled();
    }

    function _authorizeUpgrade(address) internal override {}
}
