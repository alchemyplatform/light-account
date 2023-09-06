// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "account-abstraction/samples/SimpleAccount.sol";

import "../src/LightAccount.sol";
import "../src/LightAccountFactory.sol";

contract LightAccountTest is Test {
    using stdStorage for StdStorage;

    IEntryPoint public constant ENTRY_POINT_ADDRESS = IEntryPoint(address(0x1000));

    LightAccount public account;

    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        LightAccountFactory factory = new LightAccountFactory(ENTRY_POINT_ADDRESS);
        account = factory.createAccount(address(this), 1);
    }

    function testOwnerCanTransferOwnership() public {
        address newOwner = address(0x100);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(address(this), newOwner);
        account.transferOwnership(newOwner);
        assertEq(account.owner(), newOwner);
    }

    function testNonOwnerCannotTransferOwnership() public {
        vm.prank(address(0x100));
        vm.expectRevert();
        account.transferOwnership(address(0x100));
    }

    function testOwnerCanUpgrade() public {
        // Upgrade to a normal SimpleAccount with a different entry point.
        IEntryPoint newEntryPoint = IEntryPoint(address(0x2000));
        SimpleAccount newImplementation = new SimpleAccount(newEntryPoint);
        vm.expectEmit(true, true, false, false);
        emit SimpleAccountInitialized(newEntryPoint, address(this));
        account.upgradeToAndCall(address(newImplementation), abi.encodeCall(SimpleAccount.initialize, (address(this))));
        SimpleAccount upgradedAccount = SimpleAccount(payable(account));
        assertEq(address(upgradedAccount.entryPoint()), address(newEntryPoint));
    }

    function testNonOwnerCannotUpgrade() public {
        // Try to upgrade to a normal SimpleAccount with a different entry point.
        IEntryPoint newEntryPoint = IEntryPoint(address(0x2000));
        SimpleAccount newImplementation = new SimpleAccount(newEntryPoint);
        vm.prank(address(0));
        vm.expectRevert();
        account.upgradeToAndCall(address(newImplementation), abi.encodeCall(SimpleAccount.initialize, (address(this))));
    }

    function testStorageSlots() public {
        // No storage at start (slot 0).
        bytes32 storageStart = vm.load(address(account), bytes32(uint256(0)));
        assertEq(storageStart, 0);

        // Instead, storage at the chosen locations.
        bytes32 accountSlot =
            keccak256(abi.encode(uint256(keccak256("light_account_v1.storage")) - 1)) & ~bytes32(uint256(0xff));
        address owner = abi.decode(abi.encode(vm.load(address(account), accountSlot)), (address));
        assertEq(owner, address(this));

        bytes32 initializableSlot =
            keccak256(abi.encode(uint256(keccak256("light_account_v1.initializable")) - 1)) & ~bytes32(uint256(0xff));
        uint8 initialized = abi.decode(abi.encode(vm.load(address(account), initializableSlot)), (uint8));
        assertEq(initialized, 1);
    }
}
