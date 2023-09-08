// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";

import {LightAccount} from "../src/LightAccount.sol";
import {LightAccountFactory} from "../src/LightAccountFactory.sol";

contract LightAccountTest is Test {
    using stdStorage for StdStorage;

    address public constant OWNER_ADDRESS = address(0x100);
    LightAccountFactory public factory;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new LightAccountFactory(entryPoint);
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
}
