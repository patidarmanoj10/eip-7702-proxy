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

    /**
     * Tests that complex return data (non-binary) is correctly delegated
     */
    function testDelegatesComplexReturnData() public {
        bytes memory testData = hex"deadbeef";
        // Call returnBytesData with test data
        bytes memory returnedData = MockImplementation(payable(_eoa))
            .returnBytesData(testData);

        // Verify the complex return data matches expected format
        assertEq(
            returnedData,
            testData,
            "Complex return data should be correctly delegated"
        );
    }

    /**
     * Tests that delegate call fails if read operation fails
     */
    function testDelegateFailsOnReadFailure() public {
        vm.expectRevert("MockRevert");
        MockImplementation(payable(_eoa)).revertingFunction();
    }

    /**
     * Tests that delegate call fails if write operation fails
     */
    function testDelegateFailsOnWriteFailure() public {
        // Try to call mockFunction as non-owner
        vm.prank(address(0xBAD));
        vm.expectRevert(MockImplementation.Unauthorized.selector);
        MockImplementation(payable(_eoa)).mockFunction();

        // Verify state was not changed
        assertFalse(
            MockImplementation(payable(_eoa)).mockFunctionCalled(),
            "State should not change when write fails"
        );
    }
}
