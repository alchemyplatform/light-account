// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";

import {BaseLightAccountFactory} from "../src/common/BaseLightAccountFactory.sol";
import {LightAccount} from "../src/LightAccount.sol";
import {LightAccountFactory} from "../src/LightAccountFactory.sol";

contract LightAccountFactoryTest is Test {
    using stdStorage for StdStorage;

    address public constant OWNER_ADDRESS = address(0x100);
    LightAccountFactory public factory;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new LightAccountFactory(address(this), entryPoint);
    }

    function testReturnsAddressWhenAccountAlreadyExists() public {
        LightAccount account = factory.createAccount(OWNER_ADDRESS, 1);
        LightAccount otherAccount = factory.createAccount(OWNER_ADDRESS, 1);
        assertEq(address(account), address(otherAccount));
    }

    function testGetAddress() public {
        address counterfactual = factory.getAddress(OWNER_ADDRESS, 1);
        assertEq(counterfactual.codehash, bytes32(0));
        LightAccount factual = factory.createAccount(OWNER_ADDRESS, 1);
        assertTrue(address(factual).codehash != bytes32(0));
        assertEq(counterfactual, address(factual));
    }

    function testAddStake() public {
        assertEq(entryPoint.balanceOf(address(factory)), 0);
        vm.deal(address(this), 100 ether);
        factory.addStake{value: 10 ether}(10 hours, 10 ether);
        assertEq(entryPoint.getDepositInfo(address(factory)).stake, 10 ether);
    }

    function testUnlockStake() public {
        testAddStake();
        factory.unlockStake();
        assertEq(entryPoint.getDepositInfo(address(factory)).withdrawTime, block.timestamp + 10 hours);
    }

    function testWithdrawStake() public {
        testUnlockStake();
        vm.warp(10 hours);
        vm.expectRevert("Stake withdrawal is not due");
        factory.withdrawStake(payable(address(this)));
        assertEq(address(this).balance, 90 ether);
        vm.warp(10 hours + 1);
        factory.withdrawStake(payable(address(this)));
        assertEq(address(this).balance, 100 ether);
    }

    function testWithdraw() public {
        factory.addStake{value: 10 ether}(10 hours, 1 ether);
        assertEq(address(factory).balance, 9 ether);
        factory.withdraw(payable(address(this)), address(0), 0); // amount = balance if native currency
        assertEq(address(factory).balance, 0);
    }

    function test2StepOwnershipTransfer() public {
        address owner1 = address(0x200);
        assertEq(factory.owner(), address(this));
        factory.transferOwnership(owner1);
        assertEq(factory.owner(), address(this));
        vm.prank(owner1);
        factory.acceptOwnership();
        assertEq(factory.owner(), owner1);
    }

    function testCannotRenounceOwnership() public {
        vm.expectRevert(BaseLightAccountFactory.InvalidAction.selector);
        factory.renounceOwnership();
    }

    /// @dev Receive funds from withdraw.
    receive() external payable {}
}
