// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";

import {MultiOwnerLightAccount} from "../src/MultiOwnerLightAccount.sol";
import {MultiOwnerLightAccountFactory} from "../src/MultiOwnerLightAccountFactory.sol";

contract MultiOwnerLightAccountFactoryTest is Test {
    uint256 internal constant _MAX_OWNERS_ON_CREATION = 100;

    address[] public owners;
    MultiOwnerLightAccountFactory public factory;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new MultiOwnerLightAccountFactory(entryPoint);
        owners = new address[](1);
        owners[0] = address(1);
    }

    function testReturnSameAddressWhenAccountAlreadyExists() public {
        MultiOwnerLightAccount account1 = factory.createAccountSingle(owners[0], 1);
        MultiOwnerLightAccount account2 = factory.createAccountSingle(owners[0], 1);
        MultiOwnerLightAccount account3 = factory.createAccount(owners, 1);
        assertEq(address(account1), address(account2));
        assertEq(address(account1), address(account3));
    }

    function testGetAddress() public {
        address counterfactual = factory.getAddress(owners, 1);
        assertEq(counterfactual.codehash, bytes32(0));
        MultiOwnerLightAccount factual = factory.createAccount(owners, 1);
        assertTrue(address(factual).codehash != bytes32(0));
        assertEq(counterfactual, address(factual));
    }

    function testGetAddressSingle() public {
        address counterfactual = factory.getAddress(owners, 1);
        assertEq(counterfactual.codehash, bytes32(0));
        MultiOwnerLightAccount factual = factory.createAccountSingle(owners[0], 1);
        assertTrue(address(factual).codehash != bytes32(0));
        assertEq(counterfactual, address(factual));
    }

    function testGetAddressAndCreateAccountWithMaxOwners() public {
        owners = new address[](_MAX_OWNERS_ON_CREATION);
        for (uint160 i = 0; i < _MAX_OWNERS_ON_CREATION; i++) {
            owners[i] = address(i + 1);
        }
        address counterfactual = factory.getAddress(owners, 1);
        MultiOwnerLightAccount factual = factory.createAccount(owners, 1);
        assertEq(counterfactual, address(factual));
    }

    function testGetAddressAndCreateAccountWithTooManyOwners() public {
        owners = new address[](_MAX_OWNERS_ON_CREATION + 1);
        for (uint160 i = 0; i < _MAX_OWNERS_ON_CREATION + 1; i++) {
            owners[i] = address(i + 1);
        }
        vm.expectRevert(MultiOwnerLightAccountFactory.OwnersLimitExceeded.selector);
        factory.getAddress(owners, 1);
        vm.expectRevert(MultiOwnerLightAccountFactory.OwnersLimitExceeded.selector);
        factory.createAccount(owners, 1);
    }

    function testGetAddressAndCreateAccountWithDescendingOwners() public {
        owners = new address[](3);
        owners[0] = address(100);
        owners[1] = address(99);
        owners[1] = address(98);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.getAddress(owners, 1);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.createAccount(owners, 1);
    }

    function testGetAddressAndCreateAccountWithDuplicateOwners() public {
        owners = new address[](3);
        owners[0] = address(100);
        owners[1] = address(101);
        owners[1] = address(101);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.getAddress(owners, 1);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.createAccount(owners, 1);
    }

    function testGetAddressAndCreateAccountWithZeroAddress() public {
        owners = new address[](3);
        owners[0] = address(0);
        owners[1] = address(100);
        owners[1] = address(101);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.getAddress(owners, 1);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.createAccount(owners, 1);
        vm.expectRevert(MultiOwnerLightAccountFactory.InvalidOwners.selector);
        factory.createAccountSingle(address(0), 1);
    }

    function testGetAddressAndCreateAccountWithEmptyOwners() public {
        owners = new address[](0);
        vm.expectRevert(MultiOwnerLightAccountFactory.OwnersArrayEmpty.selector);
        factory.getAddress(owners, 1);
        vm.expectRevert(MultiOwnerLightAccountFactory.OwnersArrayEmpty.selector);
        factory.createAccount(owners, 1);
    }
}
