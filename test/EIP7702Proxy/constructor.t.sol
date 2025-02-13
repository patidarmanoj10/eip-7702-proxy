// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {NonceTracker} from "../../src/NonceTracker.sol";

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {MockImplementation} from "../mocks/MockImplementation.sol";

contract ConstructorTest is EIP7702ProxyBase {
    function test_succeeds_whenAllArgumentsValid() public {
        new EIP7702Proxy(
            address(_implementation),
            _initSelector,
            _nonceTracker
        );
    }

    function test_reverts_whenImplementationZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroValueConstructorArguments.selector);
        new EIP7702Proxy(
            address(0),
            MockImplementation.initialize.selector,
            _nonceTracker
        );
    }

    function test_reverts_whenInitializerZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroValueConstructorArguments.selector);
        new EIP7702Proxy(address(_implementation), bytes4(0), _nonceTracker);
    }

    function test_reverts_whenNonceTrackerAddressZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroValueConstructorArguments.selector);
        new EIP7702Proxy(
            address(_implementation),
            _initSelector,
            NonceTracker(payable(address(0)))
        );
    }
}
