// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {CastLib} from "modular-account/helpers/CastLib.sol";
import {SetValue} from "modular-account/libraries/Constants.sol";
import {LinkedListSet, LinkedListSetLib} from "modular-account/libraries/LinkedListSetLib.sol";

import {BaseLightAccount} from "./common/BaseLightAccount.sol";
import {CustomSlotInitializable} from "./common/CustomSlotInitializable.sol";

/// @title A simple ERC-4337 compatible smart contract account with one or more designated owner accounts.
/// @dev Like LightAccount, but multiple owners are supported. The account is initialized with a list of owners,
/// and the `updateOwners` method can be used to add or remove owners.
contract MultiOwnerLightAccount is BaseLightAccount, CustomSlotInitializable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using LinkedListSetLib for LinkedListSet;
    using CastLib for address;
    using CastLib for SetValue[];

    // keccak256(abi.encode(uint256(keccak256("multi_owner_light_account_v1.storage")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _STORAGE_POSITION = 0x0eb5184329babcda7203727c83eff940fb292fc735f61720a6182b755bf7f900;
    // keccak256(abi.encode(uint256(keccak256("multi_owner_light_account_v1.initializable")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0xaa296a366a62f6551d3ddfceae892d1791068a359a0d3461aab99dfc6c5fd700;
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _LA_MSG_TYPEHASH = keccak256("MultiOwnerLightAccountMessage(bytes message)");
    bytes32 internal constant _NAME_HASH = keccak256("MultiOwnerLightAccount");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    struct LightAccountStorage {
        LinkedListSet owners;
    }

    /// @notice Emitted when this account is first initialized.
    /// @param entryPoint The entry point.
    /// @param owners The initial owners.
    event LightAccountInitialized(IEntryPoint indexed entryPoint, address[] owners);

    /// @notice This event is emitted when owners of the account are updated. Also emitted once at initialization, with
    /// an empty `removedOwners`.
    /// @param addedOwners The address array of added owners.
    /// @param removedOwners The address array of removed owners.
    event OwnersUpdated(address[] addedOwners, address[] removedOwners);

    /// @dev The account is not allowed to have 0 owners.
    error EmptyOwnersNotAllowed();

    /// @dev The owner to be added is not valid (e.g., `address(0)`, the account itself, or a current owner).
    error InvalidOwner(address owner);

    /// @dev The owner to be removed does not exist.
    error OwnerDoesNotExist(address owner);

    constructor(IEntryPoint entryPoint_) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        _ENTRY_POINT = entryPoint_;
        _disableInitializers();
    }

    /// @notice Called once as part of initialization, either during initial deployment or when first upgrading to
    /// this contract.
    /// @dev The `_ENTRY_POINT` member is immutable, to reduce gas consumption. To update the entry point address, a new
    /// implementation of LightAccount must be deployed with the new entry point address, and then `upgradeToAndCall`
    /// must be called to upgrade the implementation.
    /// @param owners_ The initial owners of the account.
    function initialize(address[] calldata owners_) public virtual initializer {
        _initialize(owners_);
    }

    /// @notice Update owners of the account. Can only be called by a current owner or from the entry point via
    /// a user operation signed by a current owner.
    /// @dev If an owner is present in both `ownersToAdd` and `ownersToRemove`, it will be added as owner. The owner
    /// array cannot have 0 or duplicate addresses.
    /// @param ownersToAdd The address array of owners to be added.
    /// @param ownersToRemove The address array of owners to be removed.
    function updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove) external virtual onlyOwner {
        _updateOwners(ownersToAdd, ownersToRemove);
    }

    ///@notice Return the owners of this account.
    ///@return The array of owner addresses.
    function owners() public view returns (address[] memory) {
        return _getStorage().owners.getAll().toAddressArray();
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
        (address recovered, ECDSA.RecoverError error,) = messageHash.tryRecover(signature);
        if (error == ECDSA.RecoverError.NoError && _getStorage().owners.contains(CastLib.toSetValue(recovered))) {
            return _1271_MAGIC_VALUE;
        }
        if (_isValidERC1271SignatureNow(messageHash, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }

    function _initialize(address[] calldata owners_) internal virtual {
        emit LightAccountInitialized(_ENTRY_POINT, owners_);
        _updateOwners(owners_, new address[](0));
    }

    function _updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove) internal {
        _removeOwnersOrRevert(ownersToRemove);
        _addOwnersOrRevert(ownersToAdd);

        if (_getStorage().owners.isEmpty()) {
            revert EmptyOwnersNotAllowed();
        }

        emit OwnersUpdated(ownersToAdd, ownersToRemove);
    }

    function _addOwnersOrRevert(address[] memory ownersToAdd) internal {
        LightAccountStorage storage _storage = _getStorage();
        uint256 length = ownersToAdd.length;
        for (uint256 i = 0; i < length; ++i) {
            address ownerToAdd = ownersToAdd[i];
            if (
                ownerToAdd == address(0) || ownerToAdd == address(this)
                    || !_storage.owners.tryAdd(ownerToAdd.toSetValue())
            ) {
                revert InvalidOwner(ownerToAdd);
            }
        }
    }

    function _removeOwnersOrRevert(address[] memory ownersToRemove) internal {
        LightAccountStorage storage _storage = _getStorage();
        uint256 length = ownersToRemove.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!_storage.owners.tryRemove(ownersToRemove[i].toSetValue())) {
                revert OwnerDoesNotExist(ownersToRemove[i]);
            }
        }
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
        bytes32 signedHash = userOpHash.toEthSignedMessageHash();
        bytes memory signature = userOp.signature;
        (address recovered, ECDSA.RecoverError error,) = signedHash.tryRecover(signature);
        if (error == ECDSA.RecoverError.NoError && _getStorage().owners.contains(recovered.toSetValue())) {
            return 0;
        }
        if (_isValidERC1271SignatureNow(userOpHash, signature)) {
            return 0;
        }
        return SIG_VALIDATION_FAILED;
    }

    function _isValidERC1271SignatureNow(bytes32 digest, bytes memory signature) internal view returns (bool) {
        LightAccountStorage storage _storage = _getStorage();
        address[] memory owners_ = _storage.owners.getAll().toAddressArray();
        uint256 length = owners_.length;
        for (uint256 i = 0; i < length; ++i) {
            if (SignatureChecker.isValidERC1271SignatureNow(owners_[i], digest, signature)) {
                return true;
            }
        }
        return false;
    }

    function _isFromOwner() internal view virtual override returns (bool) {
        return _getStorage().owners.contains(msg.sender.toSetValue());
    }

    function _getStorage() internal pure returns (LightAccountStorage storage storageStruct) {
        bytes32 position = _STORAGE_POSITION;
        assembly {
            storageStruct.slot := position
        }
    }
}
