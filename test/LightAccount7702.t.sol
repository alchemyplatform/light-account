// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {BaseLightAccount} from "../src/common/BaseLightAccount.sol";
import {LightAccount7702} from "../src/LightAccount7702.sol";

contract LightAccount7702Test is Test {
    using ECDSA for bytes32;

    uint256 public constant EOA_PRIVATE_KEY = 1;
    address payable public constant BENEFICIARY = payable(address(0xbe9ef1c1a2ee));
    bytes32 internal constant _MESSAGE_TYPEHASH = keccak256("LightAccountMessage(bytes message)");

    address public eoaAddress;
    LightAccount7702 public account;
    EntryPoint public entryPoint;
    LightSwitch public lightSwitch;

    function setUp() public {
        eoaAddress = vm.addr(EOA_PRIVATE_KEY);
        entryPoint = new EntryPoint();

        // Deploy the 7702 implementation.
        LightAccount7702 impl = new LightAccount7702(entryPoint);

        // Set up EIP-7702 delegation: EOA delegates to impl.
        Vm.SignedDelegation memory delegation = vm.signDelegation(address(impl), EOA_PRIVATE_KEY);
        vm.attachDelegation(delegation);

        // Reference the account at the EOA address.
        account = LightAccount7702(payable(eoaAddress));

        vm.deal(eoaAddress, 1 << 128);
        lightSwitch = new LightSwitch();
    }

    // -------------------------------------------------------
    // Owner
    // -------------------------------------------------------

    function testOwnerIsEOA() public view {
        assertEq(account.owner(), eoaAddress);
    }

    // -------------------------------------------------------
    // Execute
    // -------------------------------------------------------

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

    function testExecuteCanBeCalledByEntryPoint() public {
        PackedUserOperation memory op = _getSignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ()))),
            EOA_PRIVATE_KEY
        );
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, BENEFICIARY);
        assertTrue(lightSwitch.on());
    }

    function testExecuteCanBeCalledByEntryPointWithRawSignature() public {
        PackedUserOperation memory op = _getRawSignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ()))),
            EOA_PRIVATE_KEY
        );
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, BENEFICIARY);
        assertTrue(lightSwitch.on());
    }

    function testExecuteCannotBeCalledByRandos() public {
        vm.expectRevert(abi.encodeWithSelector(BaseLightAccount.NotAuthorized.selector, address(this)));
        account.execute(address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ()));
    }

    function testExecuteRevertingCallBubblesUp() public {
        Reverter reverter = new Reverter();
        vm.prank(eoaAddress);
        vm.expectRevert("did revert");
        account.execute(address(reverter), 0, abi.encodeCall(Reverter.doRevert, ()));
    }

    // -------------------------------------------------------
    // ExecuteBatch
    // -------------------------------------------------------

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
        vm.expectRevert(BaseLightAccount.ArrayLengthMismatch.selector);
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
        vm.expectRevert(BaseLightAccount.ArrayLengthMismatch.selector);
        account.executeBatch(dest, value, func);
    }

    // -------------------------------------------------------
    // Signature validation (UserOp path)
    // -------------------------------------------------------

    function testRejectsUserOpsWithInvalidSignature() public {
        PackedUserOperation memory op = _getSignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ()))),
            1234 // wrong key
        );
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function testRejectsContractSignatureType() public {
        PackedUserOperation memory op = _getUnsignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ())))
        );
        op.signature = abi.encodePacked(BaseLightAccount.SignatureType.CONTRACT, hex"deadbeef");
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodePacked(BaseLightAccount.InvalidSignatureType.selector)
            )
        );
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function testFuzz_rejectsUserOpsWithInvalidSignatureType(uint8 signatureType) public {
        signatureType = uint8(bound(signatureType, 1, type(uint8).max));

        PackedUserOperation memory op = _getUnsignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ())))
        );
        op.signature = abi.encodePacked(signatureType);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodePacked(BaseLightAccount.InvalidSignatureType.selector)
            )
        );
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function testRevertsUserOpsWithEmptySignature() public {
        PackedUserOperation memory op = _getUnsignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ())))
        );
        op.signature = hex"";
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodePacked(BaseLightAccount.InvalidSignatureType.selector)
            )
        );
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function testRevertsUserOpsWithMalformedSignature() public {
        PackedUserOperation memory op = _getUnsignedOp(
            abi.encodeCall(BaseLightAccount.execute, (address(lightSwitch), 0, abi.encodeCall(LightSwitch.turnOn, ())))
        );
        op.signature = abi.encodePacked(BaseLightAccount.SignatureType.EOA, hex"aaaa");
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, (op.signature.length - 1))
            )
        );
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    // -------------------------------------------------------
    // ERC-1271 (isValidSignature path)
    // -------------------------------------------------------

    function testIsValidSignatureForEoaOwner() public view {
        bytes32 message = keccak256("hello world");
        bytes memory signature = abi.encodePacked(
            BaseLightAccount.SignatureType.EOA, _sign(EOA_PRIVATE_KEY, _getMessageHash(abi.encode(message)))
        );
        assertEq(account.isValidSignature(message, signature), bytes4(keccak256("isValidSignature(bytes32,bytes)")));
    }

    function testIsValidSignatureForRawEoaOwner() public view {
        bytes32 message = keccak256("hello world");
        bytes memory signature = _sign(EOA_PRIVATE_KEY, _getMessageHash(abi.encode(message)));
        assertEq(account.isValidSignature(message, signature), bytes4(keccak256("isValidSignature(bytes32,bytes)")));
    }

    function testIsValidSignatureRejectsContractType() public {
        bytes32 message = keccak256("hello world");
        bytes memory signature = abi.encodePacked(BaseLightAccount.SignatureType.CONTRACT, hex"deadbeef");
        vm.expectRevert(BaseLightAccount.InvalidSignatureType.selector);
        account.isValidSignature(message, signature);
    }

    function testIsValidSignatureRejectsInvalidSigner() public view {
        bytes32 message = keccak256("hello world");
        bytes memory signature = abi.encodePacked(
            BaseLightAccount.SignatureType.EOA, _sign(123, _getMessageHash(abi.encode(message)))
        );
        assertEq(account.isValidSignature(message, signature), bytes4(0xffffffff));
    }

    function testIsValidSignatureRejectsInvalidRawSigner() public view {
        bytes32 message = keccak256("hello world");
        bytes memory signature = _sign(123, _getMessageHash(abi.encode(message)));
        assertEq(account.isValidSignature(message, signature), bytes4(0xffffffff));
    }

    function testIsValidSignatureRejectsMalformed() public {
        bytes32 message = keccak256("hello world");

        // Invalid length
        bytes memory signature =
            abi.encodePacked(BaseLightAccount.SignatureType.EOA, hex"1234567890abcdef1234567890abcdef1234567890abcdef");
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 24));
        account.isValidSignature(message, signature);

        // Empty after type byte
        signature = abi.encodePacked(BaseLightAccount.SignatureType.EOA, hex"");
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 0));
        account.isValidSignature(message, signature);

        // Raw malformed signature uses the raw path and must still be exactly 65 bytes.
        signature = hex"1234567890abcdef1234567890abcdef1234567890abcdef";
        vm.expectRevert(BaseLightAccount.InvalidSignatureType.selector);
        account.isValidSignature(message, signature);
    }

    // -------------------------------------------------------
    // Upgrade (always blocked)
    // -------------------------------------------------------

    function testUpgradeRevertsFromOwner() public {
        vm.prank(eoaAddress);
        vm.expectRevert(LightAccount7702.UpgradeNotAllowed.selector);
        account.upgradeToAndCall(address(0x1234), "");
    }

    function testUpgradeRevertsFromEntryPoint() public {
        PackedUserOperation memory op =
            _getSignedOp(abi.encodeCall(account.upgradeToAndCall, (address(0x1234), "")), EOA_PRIVATE_KEY);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        // EntryPoint catches the inner revert and emits UserOperationRevertReason instead of reverting.
        vm.expectEmit(true, true, false, false);
        emit IEntryPoint.UserOperationRevertReason(entryPoint.getUserOpHash(op), address(account), 0, "");
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    // -------------------------------------------------------
    // Initialize (always blocked)
    // -------------------------------------------------------

    function testInitializeReverts() public {
        vm.expectRevert(LightAccount7702.InitializeNotAllowed.selector);
        account.initialize(address(0x1234));
    }

    function testInitializeRevertsFromOwner() public {
        vm.prank(eoaAddress);
        vm.expectRevert(LightAccount7702.InitializeNotAllowed.selector);
        account.initialize(address(0x1234));
    }

    // -------------------------------------------------------
    // TransferOwnership (always blocked)
    // -------------------------------------------------------

    function testTransferOwnershipReverts() public {
        vm.expectRevert(LightAccount7702.TransferOwnershipNotAllowed.selector);
        account.transferOwnership(address(0x1234));
    }

    function testTransferOwnershipRevertsFromOwner() public {
        vm.prank(eoaAddress);
        vm.expectRevert(LightAccount7702.TransferOwnershipNotAllowed.selector);
        account.transferOwnership(address(0x1234));
    }

    // -------------------------------------------------------
    // EntryPoint
    // -------------------------------------------------------

    function testEntryPointGetter() public view {
        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    // -------------------------------------------------------
    // Deposit
    // -------------------------------------------------------

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

    function testWithdrawDepositCanBeCalledByEntryPoint() public {
        account.addDeposit{value: 1 ether}();
        address payable withdrawalAddress = payable(address(1));

        PackedUserOperation memory op =
            _getSignedOp(abi.encodeCall(BaseLightAccount.withdrawDepositTo, (withdrawalAddress, 5)), EOA_PRIVATE_KEY);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, BENEFICIARY);

        assertEq(withdrawalAddress.balance, 5);
    }

    function testWithdrawDepositToCannotBeCalledByRandos() public {
        account.addDeposit{value: 10}();
        vm.expectRevert(abi.encodeWithSelector(BaseLightAccount.NotAuthorized.selector, address(this)));
        account.withdrawDepositTo(BENEFICIARY, 5);
    }

    function testWithdrawDepositToZeroAddress() public {
        account.addDeposit{value: 10}();
        vm.prank(eoaAddress);
        vm.expectRevert(BaseLightAccount.ZeroAddressNotAllowed.selector);
        account.withdrawDepositTo(payable(address(0)), 5);
    }

    // -------------------------------------------------------
    // Receive ETH
    // -------------------------------------------------------

    function testCanReceiveETH() public {
        uint256 balBefore = eoaAddress.balance;
        vm.deal(address(this), 1 ether);
        (bool success,) = eoaAddress.call{value: 1 ether}("");
        assertTrue(success);
        assertEq(eoaAddress.balance, balBefore + 1 ether);
    }

    // -------------------------------------------------------
    // Contract creation
    // -------------------------------------------------------

    function testRevertCreate_IncorrectCaller() public {
        vm.expectRevert(abi.encodeWithSelector(BaseLightAccount.NotAuthorized.selector, address(this)));
        account.performCreate(0, hex"1234");
    }

    function testRevertCreate_CreateFailed() public {
        vm.prank(eoaAddress);
        vm.expectRevert(BaseLightAccount.CreateFailed.selector);
        account.performCreate(0, hex"3d3dfd");
    }

    function testRevertCreate2_IncorrectCaller() public {
        vm.expectRevert(abi.encodeWithSelector(BaseLightAccount.NotAuthorized.selector, address(this)));
        account.performCreate2(0, hex"1234", bytes32(0));
    }

    function testRevertCreate2_CreateFailed() public {
        vm.prank(eoaAddress);
        vm.expectRevert(BaseLightAccount.CreateFailed.selector);
        account.performCreate2(0, hex"3d3dfd", bytes32(0));
    }

    function testPerformCreate() public {
        vm.prank(eoaAddress);
        // Deploy minimal contract: PUSH1 0 PUSH1 0 RETURN (returns empty runtime code)
        address created = account.performCreate(0, hex"60006000f3");
        assertTrue(created != address(0));
    }

    function testPerformCreate2() public {
        vm.prank(eoaAddress);
        address created = account.performCreate2(0, hex"60006000f3", bytes32(hex"04546b"));
        assertTrue(created != address(0));
    }

    // -------------------------------------------------------
    // EIP-712 domain
    // -------------------------------------------------------

    function testDomainNameAndVersion() public view {
        (, string memory name, string memory version,,,,) = account.eip712Domain();
        assertEq(name, "LightAccount7702");
        assertEq(version, "2");
    }

    function testDomainVerifyingContract() public view {
        (,,, uint256 chainId, address verifyingContract,,) = account.eip712Domain();
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, eoaAddress);
    }

    // -------------------------------------------------------
    // Helpers
    // -------------------------------------------------------

    function _getUnsignedOp(bytes memory callData) internal view returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 1 << 24;
        uint128 callGasLimit = 1 << 24;
        uint128 maxPriorityFeePerGas = 1 << 8;
        uint128 maxFeePerGas = 1 << 8;
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: 1 << 24,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _getSignedOp(bytes memory callData, uint256 privateKey)
        internal
        view
        returns (PackedUserOperation memory)
    {
        PackedUserOperation memory op = _getUnsignedOp(callData);
        op.signature =
            abi.encodePacked(BaseLightAccount.SignatureType.EOA, _sign(privateKey, entryPoint.getUserOpHash(op)));
        return op;
    }

    function _getRawSignedOp(bytes memory callData, uint256 privateKey)
        internal
        view
        returns (PackedUserOperation memory)
    {
        PackedUserOperation memory op = _getUnsignedOp(callData);
        op.signature = _sign(privateKey, entryPoint.getUserOpHash(op));
        return op;
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _getMessageHash(bytes memory message) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(_MESSAGE_TYPEHASH, keccak256(message)));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _domainSeparator() internal view returns (bytes32) {
        (, string memory name, string memory version,,,,) = account.eip712Domain();
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(account)
            )
        );
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
