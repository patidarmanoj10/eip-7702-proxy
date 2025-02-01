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

    function test_guardedInitializer_reverts_whenCalledDirectly() public {
        bytes memory initData = abi.encodeWithSelector(
            MockImplementation.initialize.selector,
            _newOwner
        );

        vm.expectRevert(EIP7702Proxy.InvalidInitializer.selector);
        address(_eoa).call(initData);
    }

    function test_succeeds_whenReadingState() public {
        assertEq(
            MockImplementation(payable(_eoa)).owner(),
            _newOwner,
            "Delegated read call should succeed"
        );
    }

    function test_succeeds_whenWritingState() public {
        vm.prank(_newOwner);
        MockImplementation(payable(_eoa)).mockFunction();
    }

    function test_preservesReturnData_whenReturningBytes() public {
        bytes memory testData = hex"deadbeef";
        bytes memory returnedData = MockImplementation(payable(_eoa))
            .returnBytesData(testData);

        assertEq(
            returnedData,
            testData,
            "Complex return data should be correctly delegated"
        );
    }

    function test_reverts_whenReadReverts() public {
        vm.expectRevert("MockRevert");
        MockImplementation(payable(_eoa)).revertingFunction();
    }

    function test_reverts_whenWriteReverts() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(MockImplementation.Unauthorized.selector);
        MockImplementation(payable(_eoa)).mockFunction();

        assertFalse(
            MockImplementation(payable(_eoa)).mockFunctionCalled(),
            "State should not change when write fails"
        );
    }
}
