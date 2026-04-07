// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {SingleOwnerLightAccountBase} from "./SingleOwnerLightAccountBase.sol";

/// @title An ERC-4337 compatible smart contract account for EIP-7702 delegation.
/// @dev An EOA can delegate to this contract via EIP-7702 to gain ERC-4337 smart account capabilities.
///
/// Key characteristics:
///
/// 1. The owner is always `address(this)` (the delegating EOA itself). Ownership transfers are not allowed.
///
/// 2. Uses namespaced storage slots to avoid clashes when switching implementations.
///
/// 3. Upgrades are not allowed. To change implementations, the EOA should create a new 7702 delegation.
///
/// 4. Only EOA signatures are supported. For compatibility, both raw 65-byte ECDSA signatures and
/// `SignatureType.EOA || signature` are accepted. CONTRACT signature types are rejected since the owner is the
/// account itself, and contract-style signatures would create a recursive self-call.
///
/// 5. Supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature validation, allowing the delegating
/// EOA to sign messages that can be verified on-chain.
///
/// 6. Uses custom errors.
contract LightAccount7702 is SingleOwnerLightAccountBase {
    constructor(IEntryPoint entryPoint) SingleOwnerLightAccountBase(entryPoint) {}

    error UpgradeNotAllowed();
    error InitializeNotAllowed();
    error TransferOwnershipNotAllowed();

    /// @notice Upgrade the account. Not allowed.
    function upgradeToAndCall(address, bytes calldata) public payable override {
        revert UpgradeNotAllowed();
    }

    /// @notice Initialize the account. Not allowed.
    function initialize(address) external virtual {
        revert InitializeNotAllowed();
    }

    /// @notice Transfer ownership. Not allowed.
    function transferOwnership(address) external virtual {
        revert TransferOwnershipNotAllowed();
    }

    /// @notice Return the current owner of this account.
    /// @return The current owner is the account itself in EIP-7702
    function owner() public view override returns (address) {
        return address(this);
    }

    /// @dev Only EOA signatures are supported for 7702 accounts. CONTRACT signature type would cause
    /// a recursive call since owner() == address(this).
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        return _successToValidationData(_isValidEOAOwnerSignatureWithOptionalPrefix(userOpHash, userOp.signature));
    }

    /// @dev Only EOA signatures are supported for 7702 accounts. CONTRACT signature type would cause
    /// a recursive call since owner() == address(this).
    function _isValidSignature(bytes32 replaySafeHash, bytes calldata signature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        return _isValidEOAOwnerSignatureWithOptionalPrefix(replaySafeHash, signature);
    }

    /// @dev Contract owner signatures are not supported for 7702 accounts because owner() == address(this),
    /// which would cause a recursive call to isValidSignature.
    function _isValidContractOwnerSignatureNow(bytes32, bytes memory) internal pure override returns (bool) {
        revert InvalidSignatureType();
    }

    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "LightAccount7702";
        // Set to the major version of the GitHub release at which the contract was last updated.
        version = "2";
    }

    /// @dev Parse raw 65-byte ECDSA signatures, or `SignatureType.EOA || signature`.
    /// Length-based parsing avoids treating a raw signature whose first byte is `0x00` as prefixed.
    function _isValidEOAOwnerSignatureWithOptionalPrefix(bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length == 65) {
            return _isValidEOAOwnerSignature(digest, signature);
        }
        if (signature.length == 66) {
            if (uint8(signature[0]) != uint8(SignatureType.EOA)) {
                revert InvalidSignatureType();
            }
            return _isValidEOAOwnerSignature(digest, signature[1:]);
        }
        if (signature.length > 0 && uint8(signature[0]) == uint8(SignatureType.EOA)) {
            revert ECDSA.ECDSAInvalidSignatureLength(signature.length - 1);
        }
        revert InvalidSignatureType();
    }
}
