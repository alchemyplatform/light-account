// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {CustomSlotInitializable} from "../src/common/CustomSlotInitializable.sol";

contract CustomSlotInitializableTest is Test {
    using stdStorage for StdStorage;

    event Initialized(uint64 version);

    address v1Impl;
    address v2Impl;
    V1 v1Proxy;

    function setUp() public {
        v1Impl = address(new V1());
        v2Impl = address(new V2());
        v1Proxy = V1(address(new ERC1967Proxy(v1Impl, abi.encodeCall(V1.initialize, ()))));
    }

    function testSimpleInitialization() public {
        V1 v1 = new V1();
        vm.expectEmit(false, false, false, true);
        emit Initialized(1);
        v1.initialize();
        assertEq(v1.getInitializedVersion(), 1);
    }

    function testUpgrade() public {
        vm.expectEmit(false, false, false, true);
        emit Initialized(2);
        v1Proxy.upgradeToAndCall(v2Impl, abi.encodeCall(V2.initialize, ()));
        V2 v2Proxy = V2(address(v1Proxy));
        assertEq(v2Proxy.getInitializedVersion(), 2);
    }

    function testCannotReinitialize() public {
        vm.expectRevert(CustomSlotInitializable.InvalidInitialization.selector);
        v1Proxy.upgradeToAndCall(v1Impl, abi.encodeCall(V1.initialize, ()));
    }

    function testCannotUpgradeBackwards() public {
        v1Proxy.upgradeToAndCall(v2Impl, abi.encodeCall(V2.initialize, ()));
        V2 v2Proxy = V2(address(v1Proxy));
        vm.expectRevert(CustomSlotInitializable.InvalidInitialization.selector);
        v2Proxy.upgradeToAndCall(v1Impl, abi.encodeCall(V1.initialize, ()));
    }

    function testDisableInitializers() public {
        v1Proxy.disableInitializers();
        vm.expectRevert(CustomSlotInitializable.InvalidInitialization.selector);
        v1Proxy.upgradeToAndCall(v2Impl, abi.encodeCall(V2.initialize, ()));
    }

    function testCannotCallDisableInitializersInInitializer() public {
        DisablesInitializersWhileInitializing account = new DisablesInitializersWhileInitializing();
        vm.expectRevert(CustomSlotInitializable.InvalidInitialization.selector);
        account.initialize();
    }

    function testIsInitializing() public {
        IsInitializingChecker checker = new IsInitializingChecker();
        checker.initialize();
        assertTrue(checker.wasInitializing());
        assertFalse(checker.isInitializing());
    }
}

contract V1 is CustomSlotInitializable(keccak256("storage")), UUPSUpgradeable {
    function initialize() public initializer {}

    function getInitializedVersion() public view returns (uint64) {
        return _getInitializedVersion();
    }

    function disableInitializers() public {
        _disableInitializers();
    }

    function _authorizeUpgrade(address newImplementation) internal pure override {
        (newImplementation);
    }
}

contract V2 is CustomSlotInitializable(keccak256("storage")), UUPSUpgradeable {
    function initialize() public reinitializer(2) {}

    function getInitializedVersion() public view returns (uint64) {
        return _getInitializedVersion();
    }

    function _authorizeUpgrade(address newImplementation) internal pure override {
        (newImplementation);
    }
}

contract DisablesInitializersWhileInitializing is CustomSlotInitializable(keccak256("storage")) {
    function initialize() public initializer {
        _disableInitializers();
    }
}

contract IsInitializingChecker is CustomSlotInitializable(keccak256("storage")) {
    bool public wasInitializing;

    function initialize() public initializer {
        wasInitializing = _isInitializing();
    }

    function isInitializing() public view returns (bool) {
        return _isInitializing();
    }
}
