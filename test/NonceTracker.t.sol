// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {NonceTracker} from "../src/NonceTracker.sol";

contract NonceTrackerTest is Test {
    NonceTracker public nonceTracker;
    address public account;
    uint256 constant ACCOUNT_PK = 0xA11CE;

    event NonceUsed(address indexed account, uint256 nonce);

    function setUp() public {
        nonceTracker = new NonceTracker();
        account = vm.addr(ACCOUNT_PK);
    }

    function test_getNextNonce_initialNonceIsZero() public {
        assertEq(nonceTracker.getNextNonce(account), 0, "Initial nonce should be zero");
    }

    function test_getNextNonce_incrementsNonce_afterVerification() public {
        uint256 nonce = nonceTracker.getNextNonce(account);

        vm.prank(account);
        nonceTracker.verifyAndUseNonce(nonce);
        assertEq(nonceTracker.getNextNonce(account), nonce + 1, "Nonce should increment after use");
    }

    function test_getNextNonce_emitsEvent_whenNonceUsed() public {
        uint256 nonce = nonceTracker.getNextNonce(account);

        vm.expectEmit(true, false, false, true);
        emit NonceUsed(account, nonce);
        vm.prank(account);
        nonceTracker.verifyAndUseNonce(nonce);
    }

    function test_verifyAndUseNonce_reverts_whenNonceInvalid(uint256 invalidNonce) public {
        uint256 expectedNonce = nonceTracker.getNextNonce(account);
        vm.assume(invalidNonce != expectedNonce);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(NonceTracker.InvalidNonce.selector, expectedNonce, invalidNonce));
        nonceTracker.verifyAndUseNonce(invalidNonce);
    }

    function test_getNextNonce_maintainsCorrectNonce_afterMultipleIncrements(uint8 incrementCount) public {
        uint256 expectedNonce = 0;

        for (uint256 i = 0; i < incrementCount; i++) {
            assertEq(nonceTracker.getNextNonce(account), expectedNonce, "Incorrect nonce before increment");

            vm.prank(account);
            nonceTracker.verifyAndUseNonce(expectedNonce);

            expectedNonce++;
        }

        assertEq(nonceTracker.getNextNonce(account), expectedNonce, "Final nonce incorrect");
    }

    function test_getNextNonce_tracksNoncesIndependently_forDifferentAccounts(address otherAccount) public {
        vm.assume(otherAccount != account);

        // Use account's nonce
        uint256 accountNonce = nonceTracker.getNextNonce(account);
        vm.prank(account);
        nonceTracker.verifyAndUseNonce(accountNonce);

        // Other account's nonce should still be 0
        assertEq(nonceTracker.getNextNonce(otherAccount), 0, "Other account's nonce should be independent");
    }

    function test_verifyAndUseNonce_reverts_whenReusingNonce() public {
        uint256 nonce = nonceTracker.getNextNonce(account);

        // Use nonce first time
        vm.prank(account);
        nonceTracker.verifyAndUseNonce(nonce);

        // Try to reuse same nonce
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(NonceTracker.InvalidNonce.selector, nonce + 1, nonce));
        nonceTracker.verifyAndUseNonce(nonce);
    }

    function test_verifyAndUseNonce_reverts_whenCallerNotAccount(address caller) public {
        vm.assume(caller != account);

        // Get nonces for both accounts
        uint256 accountNonce = nonceTracker.getNextNonce(account);
        uint256 callerNonce = nonceTracker.getNextNonce(caller);

        // Use caller's nonce to make sure it's different from account's
        vm.prank(caller);
        nonceTracker.verifyAndUseNonce(callerNonce);

        // Try to use account's nonce from a different address
        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(
                NonceTracker.InvalidNonce.selector,
                callerNonce + 1, // expected nonce has incremented
                accountNonce // actual nonce
            )
        );
        nonceTracker.verifyAndUseNonce(accountNonce);
    }
}
