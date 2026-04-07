// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {BaseLightAccount} from "./common/BaseLightAccount.sol";
import {CustomSlotInitializable} from "./common/CustomSlotInitializable.sol";

/// @title Base contract for single-owner LightAccount variants.
/// @dev Provides shared storage layout, owner resolution helpers, and signature validation utilities.
/// Concrete implementations must override `owner()` and the signature validation functions.
abstract contract SingleOwnerLightAccountBase is BaseLightAccount, CustomSlotInitializable {
    using ECDSA for bytes32;

    /// @dev The version used for namespaced storage is not linked to the release version of the contract. Storage
    /// versions will be updated only when storage layout changes are made.
    /// keccak256(abi.encode(uint256(keccak256("light_account_v1.storage")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _STORAGE_POSITION = 0x691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be512200;
    /// @dev keccak256(abi.encode(uint256(keccak256("light_account_v1.initializable")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0x33e4b41198cc5b8053630ed667ea7c0c4c873f7fc8d9a478b5d7259cec0a4a00;

    struct LightAccountStorage {
        address owner;
    }

    constructor(IEntryPoint entryPoint_) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        _ENTRY_POINT = entryPoint_;
        _disableInitializers();
    }

    function owner() public view virtual returns (address);

    function _isFromOwner() internal view override returns (bool) {
        return msg.sender == owner();
    }

    /// @notice Check if the signature is a valid by the EOA owner for the given digest.
    /// @dev Only supports 65-byte signatures, and uses the digest directly. Reverts if the signature is malformed.
    /// @param digest The digest to be checked.
    /// @param signature The signature to be checked.
    /// @return True if the signature is valid and by the owner, false otherwise.
    function _isValidEOAOwnerSignature(bytes32 digest, bytes memory signature) internal view returns (bool) {
        address recovered = digest.recover(signature);
        return recovered == owner();
    }

    /// @notice Check if the signature is a valid ERC-1271 signature by a contract owner for the given digest.
    /// @param digest The digest to be checked.
    /// @param signature The signature to be checked.
    /// @return True if the signature is valid and by an owner, false otherwise.
    function _isValidContractOwnerSignatureNow(bytes32 digest, bytes memory signature) internal view virtual returns (bool) {
        return SignatureChecker.isValidERC1271SignatureNow(owner(), digest, signature);
    }

    function _getStorage() internal pure returns (LightAccountStorage storage storageStruct) {
        bytes32 position = _STORAGE_POSITION;
        assembly ("memory-safe") {
            storageStruct.slot := position
        }
    }
}
