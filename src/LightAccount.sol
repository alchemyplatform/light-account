// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {BaseLightAccount} from "./common/BaseLightAccount.sol";
import {CustomSlotInitializable} from "./common/CustomSlotInitializable.sol";

/// @title A simple ERC-4337 compatible smart contract account with a designated owner account.
/// @dev Like eth-infinitism's SimpleAccount, but with the following changes:
///
/// 1. Instead of the default storage slots, uses namespaced storage to avoid clashes when switching implementations.
///
/// 2. Ownership can be transferred via `transferOwnership`, similar to the behavior of an `Ownable` contract. This is
/// a simple single-step operation, so care must be taken to ensure that the ownership is being transferred to the
/// correct address.
///
/// 3. Supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature validation for both validating the
/// signature on user operations and in exposing its own `isValidSignature` method. This only works when the owner of
/// LightAccount also support ERC-1271.
///
/// ERC-4337's bundler validation rules limit the types of contracts that can be used as owners to validate user
/// operation signatures. For example, the contract's `isValidSignature` function may not use any forbidden opcodes
/// such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967 proxy as it accesses a constant
/// implementation slot not associated with the account, violating storage access rules. This also means that the
/// owner of a LightAccount may not be another LightAccount if you want to send user operations through a bundler.
///
/// 4. Event `SimpleAccountInitialized` renamed to `LightAccountInitialized`.
///
/// 5. Uses custom errors.
contract LightAccount is BaseLightAccount, CustomSlotInitializable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // keccak256(abi.encode(uint256(keccak256("light_account_v1.storage")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _STORAGE_POSITION = 0x691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be512200;
    // keccak256(abi.encode(uint256(keccak256("light_account_v1.initializable")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0x33e4b41198cc5b8053630ed667ea7c0c4c873f7fc8d9a478b5d7259cec0a4a00;
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _LA_MSG_TYPEHASH = keccak256("LightAccountMessage(bytes message)");
    bytes32 internal constant _NAME_HASH = keccak256("LightAccount");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    struct LightAccountStorage {
        address owner;
    }

    /// @notice Emitted when this account is first initialized.
    /// @param entryPoint The entry point.
    /// @param owner The initial owner.
    event LightAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    /// @notice Emitted when this account's owner changes. Also emitted once at initialization, with a
    /// `previousOwner` of 0.
    /// @param previousOwner The previous owner.
    /// @param newOwner The new owner.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @dev The new owner is not a valid owner (e.g., `address(0)`, the account itself, or the current owner).
    error InvalidOwner(address owner);

    constructor(IEntryPoint entryPoint_) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        _ENTRY_POINT = entryPoint_;
        _disableInitializers();
    }

    /// @notice Called once as part of initialization, either during initial deployment or when first upgrading to
    /// this contract.
    /// @dev The `_ENTRY_POINT` member is immutable, to reduce gas consumption. To update the entry point address, a new
    /// implementation of LightAccount must be deployed with the new entry point address, and then `upgradeToAndCall`
    /// must be called to upgrade the implementation.
    /// @param owner_ The initial owner of the account.
    function initialize(address owner_) public virtual initializer {
        _initialize(owner_);
    }

    /// @notice Transfers ownership of the contract to a new account (`newOwner`). Can only be called by the current
    /// owner or from the entry point via a user operation signed by the current owner.
    /// @param newOwner The new owner.
    function transferOwnership(address newOwner) external virtual onlyOwner {
        if (newOwner == address(0) || newOwner == address(this)) {
            revert InvalidOwner(newOwner);
        }
        _transferOwnership(newOwner);
    }

    /// @notice Return the current owner of this account.
    /// @return The current owner.
    function owner() public view returns (address) {
        return _getStorage().owner;
    }

    /// @notice Returns the domain separator for this contract, as defined in the EIP-712 standard.
    /// @return bytes32 The domain separator hash.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _DOMAIN_SEPARATOR_TYPEHASH,
                _NAME_HASH, // name
                _VERSION_HASH, // version
                block.chainid, // chainId
                address(this) // verifying contract
            )
        );
    }

    /// @notice Returns the pre-image of the message hash.
    /// @param message Message that should be encoded.
    /// @return Encoded message.
    function encodeMessageData(bytes memory message) public view returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encode(_LA_MSG_TYPEHASH, keccak256(message)));
        return abi.encodePacked("\x19\x01", domainSeparator(), messageHash);
    }

    /// @notice Returns hash of a message that can be signed by owners.
    /// @param message Message that should be hashed.
    /// @return Message hash.
    function getMessageHash(bytes memory message) public view returns (bytes32) {
        return keccak256(encodeMessageData(message));
    }

    /// @inheritdoc IERC1271
    /// @dev The signature is valid if it is signed by the owner's private key (if the owner is an EOA) or if it is a
    /// valid ERC-1271 signature from the owner (if the owner is a contract). Note that unlike the signature validation
    /// used in `validateUserOp`, this does **not** wrap the digest in an "Ethereum Signed Message" envelope before
    /// checking the signature in the EOA-owner case.
    function isValidSignature(bytes32 hash, bytes memory signature) public view override returns (bytes4) {
        bytes32 messageHash = getMessageHash(abi.encode(hash));
        if (SignatureChecker.isValidSignatureNow(owner(), messageHash, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }

    function _initialize(address owner_) internal virtual {
        if (owner_ == address(0)) {
            revert InvalidOwner(address(0));
        }
        _getStorage().owner = owner_;
        emit LightAccountInitialized(_ENTRY_POINT, owner_);
        emit OwnershipTransferred(address(0), owner_);
    }

    function _transferOwnership(address newOwner) internal virtual {
        LightAccountStorage storage _storage = _getStorage();
        address oldOwner = _storage.owner;
        if (newOwner == oldOwner) {
            revert InvalidOwner(newOwner);
        }
        _storage.owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /// @dev Implement template method of BaseAccount.
    /// Uses a modified version of `SignatureChecker.isValidSignatureNow` in which the digest is wrapped with an
    /// "Ethereum Signed Message" envelope for the EOA-owner case but not in the ERC-1271 contract-owner case.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        address _owner = owner();
        bytes32 signedHash = userOpHash.toEthSignedMessageHash();
        bytes memory signature = userOp.signature;
        (address recovered, ECDSA.RecoverError error,) = signedHash.tryRecover(signature);
        if (
            (error == ECDSA.RecoverError.NoError && recovered == _owner)
                || SignatureChecker.isValidERC1271SignatureNow(_owner, userOpHash, signature)
        ) {
            return 0;
        }
        return SIG_VALIDATION_FAILED;
    }

    function _isFromOwner() internal view virtual override returns (bool) {
        return msg.sender == owner();
    }

    function _getStorage() internal pure returns (LightAccountStorage storage storageStruct) {
        bytes32 position = _STORAGE_POSITION;
        assembly {
            storageStruct.slot := position
        }
    }
}
