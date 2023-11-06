// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {SimpleAccount} from "account-abstraction/samples/SimpleAccount.sol";

import {LightAccount} from "../src/LightAccount.sol";
import {LightAccountFactory} from "../src/LightAccountFactory.sol";

contract LightAccountTest is Test {
    using stdStorage for StdStorage;
    using ECDSA for bytes32;

    uint256 public constant EOA_PRIVATE_KEY = 1;
    address payable public constant BENEFICIARY = payable(address(0xbe9ef1c1a2ee));
    address public eoaAddress;
    LightAccount public account;
    LightAccount public contractOwnedAccount;
    EntryPoint public entryPoint;
    LightSwitch public lightSwitch;
    Owner public contractOwner;

    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Initialized(uint64 version);

    function setUp() public {
        eoaAddress = vm.addr(EOA_PRIVATE_KEY);
        entryPoint = new EntryPoint();
        LightAccountFactory factory = new LightAccountFactory(entryPoint);
        account = factory.createAccount(eoaAddress, 1);
        vm.deal(address(account), 1 << 128);
        lightSwitch = new LightSwitch();
        contractOwner = new Owner();
    }

    function testExecuteCanBeCalledByOwner() public {
        vm.prank(eoaAddress);
        account.execute(address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ()));
        assertTrue(lightSwitch.on());
    }

    function testExecuteWithValueCanBeCalledByOwner() public {
        vm.prank(eoaAddress);
        account.execute(address(lightSwitch), 1 ether, abi.encodeCall(LightSwitch.turnOn, ()));
        assertTrue(lightSwitch.on());
        assertEq(address(lightSwitch).balance, 1 ether);
    }

    function testExecuteCanBeCalledByEntryPointWithExternalOwner() public {
        UserOperation memory op =
            _getSignedOp(address(lightSwitch), abi.encodeCall(LightSwitch.turnOn, ()), EOA_PRIVATE_KEY);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, BENEFICIARY);
        assertTrue(lightSwitch.on());
    }

    function testExecutedCanBeCalledByEntryPointWithContractOwner() public {
        _useContractOwner();
        UserOperation memory op = _getUnsignedOp(address(lightSwitch), abi.encodeCall(LightSwitch.turnOn, ()));
        op.signature = contractOwner.sign(entryPoint.getUserOpHash(op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, BENEFICIARY);
        assertTrue(lightSwitch.on());
    }

    function testRejectsUserOpsWithInvalidSignature() public {
        UserOperation memory op = _getSignedOp(address(lightSwitch), abi.encodeCall(LightSwitch.turnOn, ()), 1234);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function testExecuteCannotBeCalledByRandos() public {
        vm.expectRevert(abi.encodeWithSelector(LightAccount.NotAuthorized.selector, (address(this))));
        account.execute(address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ()));
    }

    function testExecuteRevertingCallShouldRevertWithSameData() public {
        Reverter reverter = new Reverter();
        vm.prank(eoaAddress);
        vm.expectRevert("did revert");
        account.execute(address(reverter), 0, abi.encodeCall(Reverter.doRevert, ()));
    }

    function testExecuteBatchCalledByOwner() public {
        vm.prank(eoaAddress);
        address[] memory dest = new address[](1);
        dest[0] = address(lightSwitch);
        bytes[] memory func = new bytes[](1);
        func[0] = abi.encodeCall(LightSwitch.turnOn, ());
        account.executeBatch(dest, func);
        assertTrue(lightSwitch.on());
    }

    function testExecuteBatchFailsForUnevenInputArrays() public {
        vm.prank(eoaAddress);
        address[] memory dest = new address[](2);
        dest[0] = address(lightSwitch);
        dest[1] = address(lightSwitch);
        bytes[] memory func = new bytes[](1);
        func[0] = abi.encodeCall(LightSwitch.turnOn, ());
        vm.expectRevert(LightAccount.ArrayLengthMismatch.selector);
        account.executeBatch(dest, func);
    }

    function testExecuteBatchWithValueCalledByOwner() public {
        vm.prank(eoaAddress);
        address[] memory dest = new address[](1);
        dest[0] = address(lightSwitch);
        uint256[] memory value = new uint256[](1);
        value[0] = uint256(1);
        bytes[] memory func = new bytes[](1);
        func[0] = abi.encodeCall(LightSwitch.turnOn, ());
        account.executeBatch(dest, value, func);
        assertTrue(lightSwitch.on());
        assertEq(address(lightSwitch).balance, 1);
    }

    function testExecuteBatchWithValueFailsForUnevenInputArrays() public {
        vm.prank(eoaAddress);
        address[] memory dest = new address[](1);
        dest[0] = address(lightSwitch);
        uint256[] memory value = new uint256[](2);
        value[0] = uint256(1);
        value[1] = uint256(1 ether);
        bytes[] memory func = new bytes[](1);
        func[0] = abi.encodeCall(LightSwitch.turnOn, ());
        vm.expectRevert(LightAccount.ArrayLengthMismatch.selector);
        account.executeBatch(dest, value, func);
    }

    function testInitialize() public {
        LightAccountFactory factory = new LightAccountFactory(entryPoint);
        vm.expectEmit(true, false, false, false);
        emit Initialized(0);
        account = factory.createAccount(eoaAddress, 1);
    }

    function testCannotInitializeWithZeroOwner() public {
        LightAccountFactory factory = new LightAccountFactory(entryPoint);
        vm.expectRevert(abi.encodeWithSelector(LightAccount.InvalidOwner.selector, (address(0))));
        account = factory.createAccount(address(0), 1);
    }

    function testAddDeposit() public {
        assertEq(account.getDeposit(), 0);
        account.addDeposit{value: 10}();
        assertEq(account.getDeposit(), 10);
        assertEq(account.getDeposit(), entryPoint.balanceOf(address(account)));
    }

    function testWithdrawDepositToCalledByOwner() public {
        account.addDeposit{value: 10}();
        vm.prank(eoaAddress);
        account.withdrawDepositTo(BENEFICIARY, 5);
        assertEq(entryPoint.balanceOf(address(account)), 5);
    }

    function testWithdrawDepositToCannotBeCalledByRandos() public {
        account.addDeposit{value: 10}();
        vm.expectRevert(abi.encodeWithSelector(LightAccount.NotAuthorized.selector, (address(this))));
        account.withdrawDepositTo(BENEFICIARY, 5);
    }

    function testOwnerCanTransferOwnership() public {
        address newOwner = address(0x100);
        vm.prank(eoaAddress);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(eoaAddress, newOwner);
        account.transferOwnership(newOwner);
        assertEq(account.owner(), newOwner);
    }

    function testEntryPointCanTransferOwnership() public {
        address newOwner = address(0x100);
        UserOperation memory op =
            _getSignedOp(address(account), abi.encodeCall(LightAccount.transferOwnership, (newOwner)), EOA_PRIVATE_KEY);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(eoaAddress, newOwner);
        entryPoint.handleOps(ops, BENEFICIARY);
        assertEq(account.owner(), newOwner);
    }

    function testRandosCannotTransferOwnership() public {
        vm.expectRevert(abi.encodeWithSelector(LightAccount.NotAuthorized.selector, (address(this))));
        account.transferOwnership(address(0x100));
    }

    function testCannotTransferOwnershipToCurrentOwner() public {
        vm.prank(eoaAddress);
        vm.expectRevert(abi.encodeWithSelector(LightAccount.InvalidOwner.selector, (eoaAddress)));
        account.transferOwnership(eoaAddress);
    }

    function testCannotTransferOwnershipToZero() public {
        vm.prank(eoaAddress);
        vm.expectRevert(abi.encodeWithSelector(LightAccount.InvalidOwner.selector, (address(0))));
        account.transferOwnership(address(0));
    }

    function testCannotTransferOwnershipToLightContractItself() public {
        vm.prank(eoaAddress);
        vm.expectRevert(abi.encodeWithSelector(LightAccount.InvalidOwner.selector, (address(account))));
        account.transferOwnership(address(account));
    }

    function testEntryPointGetter() public {
        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function testIsValidSignatureForEoaOwner() public {
        bytes32 digest = keccak256("digest");
        bytes memory signature = _sign(EOA_PRIVATE_KEY, account.getMessageHash(abi.encode(digest)));
        assertEq(account.isValidSignature(digest, signature), bytes4(keccak256("isValidSignature(bytes32,bytes)")));
    }

    function testIsValidSignatureForContractOwner() public {
        _useContractOwner();
        bytes32 digest = keccak256("digest");
        bytes memory signature = contractOwner.sign(account.getMessageHash(abi.encode(digest)));
        assertEq(account.isValidSignature(digest, signature), bytes4(keccak256("isValidSignature(bytes32,bytes)")));
    }

    function testIsValidSignatureRejectsInvalid() public {
        bytes32 digest = keccak256("digest");
        bytes memory signature = _sign(123, account.getMessageHash(abi.encode(digest)));
        assertEq(account.isValidSignature(digest, signature), bytes4(0xffffffff));
    }

    function testOwnerCanUpgrade() public {
        // Upgrade to a normal SimpleAccount with a different entry point.
        IEntryPoint newEntryPoint = IEntryPoint(address(0x2000));
        SimpleAccount newImplementation = new SimpleAccount(newEntryPoint);
        vm.expectEmit(true, true, false, false);
        emit SimpleAccountInitialized(newEntryPoint, address(this));
        vm.prank(eoaAddress);
        account.upgradeToAndCall(address(newImplementation), abi.encodeCall(SimpleAccount.initialize, (address(this))));
        SimpleAccount upgradedAccount = SimpleAccount(payable(account));
        assertEq(address(upgradedAccount.entryPoint()), address(newEntryPoint));
    }

    function testNonOwnerCannotUpgrade() public {
        // Try to upgrade to a normal SimpleAccount with a different entry point.
        IEntryPoint newEntryPoint = IEntryPoint(address(0x2000));
        SimpleAccount newImplementation = new SimpleAccount(newEntryPoint);
        vm.expectRevert(abi.encodeWithSelector(LightAccount.NotAuthorized.selector, (address(this))));
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
        assertEq(owner, eoaAddress);

        bytes32 initializableSlot =
            keccak256(abi.encode(uint256(keccak256("light_account_v1.initializable")) - 1)) & ~bytes32(uint256(0xff));
        uint8 initialized = abi.decode(abi.encode(vm.load(address(account), initializableSlot)), (uint8));
        assertEq(initialized, 1);
    }

    function testValidateInitCodeHash() external {
        assertEq(
            keccak256(
                abi.encodePacked(
                    type(LightAccountFactory).creationCode,
                    bytes32(uint256(uint160(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)))
                )
            ),
            0x2ad62a8bb3850247ef0c4f04e30b584e6eee7caa0e063745e90956653b90eb84
        );
    }

    function _useContractOwner() internal {
        vm.prank(eoaAddress);
        account.transferOwnership(address(contractOwner));
    }

    function _getUnsignedOp(address target, bytes memory innerCallData) internal view returns (UserOperation memory) {
        return UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(LightAccount.execute, (target, 0, innerCallData)),
            callGasLimit: 1 << 24,
            verificationGasLimit: 1 << 24,
            preVerificationGas: 1 << 24,
            maxFeePerGas: 1 << 8,
            maxPriorityFeePerGas: 1 << 8,
            paymasterAndData: "",
            signature: ""
        });
    }

    function _getSignedOp(address target, bytes memory innerCallData, uint256 privateKey)
        internal
        view
        returns (UserOperation memory)
    {
        UserOperation memory op = _getUnsignedOp(target, innerCallData);
        op.signature = _sign(privateKey, entryPoint.getUserOpHash(op).toEthSignedMessageHash());
        return op;
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}

contract LightSwitch {
    bool public on;

    function turnOn() external payable {
        on = true;
    }
}

contract Reverter {
    function doRevert() external pure {
        revert("did revert");
    }
}

contract Owner is IERC1271 {
    function sign(bytes32 digest) public pure returns (bytes memory) {
        return abi.encodePacked("Signed: ", digest);
    }

    function isValidSignature(bytes32 digest, bytes memory signature) public pure override returns (bytes4) {
        if (keccak256(signature) == keccak256(sign(digest))) {
            return bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        }
        return 0xffffffff;
    }
}
