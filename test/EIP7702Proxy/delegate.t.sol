// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {MockImplementation} from "../mocks/MockImplementation.sol";

contract DelegateTest is EIP7702ProxyBase {
    function setUp() public override {
        super.setUp();

        // Initialize the proxy
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function testBlocksGuardedInitializer() public {
        bytes memory initData = abi.encodeWithSelector(
            MockImplementation.initialize.selector,
            _newOwner
        );

        vm.expectRevert(EIP7702Proxy.InvalidInitializer.selector);
        address(_eoa).call(initData);
    }

    function testDelegatesReadCall() public {
        assertEq(
            MockImplementation(payable(_eoa)).owner(),
            _newOwner,
            "Delegated read call should succeed"
        );
    }

    function testDelegatesWriteCall() public {
        vm.prank(_newOwner);
        MockImplementation(payable(_eoa)).mockFunction();
        // Success is just completing the call without revert
    }
}
