// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EIP712} from "../external/solady/EIP712.sol";

/// @title ERC-1271 implementation using nested EIP-712 for replay protection.
/// @dev Identical to Solady's ERC1271, with a minor change to support overriding the signature verification logic.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
/// @author Alchemy
abstract contract ERC1271 is EIP712 {
    /// @dev Validates the signature with ERC1271 return,
    /// so that this account can also be used as a signer.
    ///
    /// This implementation uses ECDSA recovery. It also uses a nested EIP-712 approach to
    /// prevent signature replays when a single EOA owns multiple smart contract accounts,
    /// while still enabling wallet UIs (e.g. Metamask) to show the EIP-712 values.
    ///
    /// For the nested EIP-712 workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 || DOMAIN_SEP_A ||
    ///         hashStruct(Parent({
    ///             childHash: keccak256(\x19\x01 || DOMAIN_SEP_B || hashStruct(originalStruct)),
    ///             child: hashStruct(originalStruct)
    ///         }))
    ///     )
    /// ```
    /// where `||` denotes the concatenation operator for bytes.
    /// The signature will be `r || s || v || PARENT_TYPEHASH || DOMAIN_SEP_B || child`.
    ///
    /// The `DOMAIN_SEP_B` and `child` will be used to verify if `childHash` is indeed correct.
    ///
    /// For the `personal_sign` workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 || DOMAIN_SEP_A ||
    ///         hashStruct(Parent({
    ///             childHash: personalSign(someBytes)
    ///         }))
    ///     )
    /// ```
    /// where `||` denotes the concatenation operator for bytes.
    /// The signature will be `r || s || v || PARENT_TYPEHASH`.
    ///
    /// For demo and typescript code, see:
    /// - https://github.com/junomonster/nested-eip-712
    /// - https://github.com/frangio/eip712-wrapper-for-eip1271
    ///
    /// Of course, if you are a wallet app maker and can update your app's UI at will,
    /// you can choose a more minimalistic signature scheme like
    /// `keccak256(abi.encode(address(this), hash))` instead of all these acrobatics.
    /// All these are just for widespead out-of-the-box compatibility with other wallet apps.
    ///
    /// The `hash` parameter is the `childHash`.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            let o := add(signature.offset, sub(signature.length, 0x60))
            calldatacopy(0x00, o, 0x60) // Copy the `DOMAIN_SEP_B` and child's structHash.
            mstore(0x00, 0x1901) // Store the "\x19\x01" prefix, overwriting 0x00.
            for {} 1 {} {
                // Use the nested EIP-712 workflow if the reconstructed childHash matches,
                // and the signature is at least 96 bytes long.
                if iszero(or(xor(keccak256(0x1e, 0x42), hash), lt(signature.length, 0x60))) {
                    // Truncate the `signature.length` by 3 words (96 bytes).
                    signature.length := sub(signature.length, 0x60)
                    mstore(0x00, calldataload(o)) // Store the `PARENT_TYPEHASH`.
                    mstore(0x20, hash) // Store the `childHash`.
                    // The child's structHash is already at 0x40.
                    hash := keccak256(0x00, 0x60) // Compute the parent's structHash.
                    break
                }
                // Else, use the `personal_sign` workflow.
                // Truncate the `signature.length` by 1 word (32 bytes), until zero.
                signature.length := mul(gt(signature.length, 0x20), sub(signature.length, 0x20))
                // The `PARENT_TYPEHASH` is already at 0x40.
                mstore(0x60, hash) // Store the `childHash`.
                hash := keccak256(0x40, 0x40) // Compute the parent's structHash.
                mstore(0x60, 0) // Restore the zero pointer.
                break
            }
            mstore(0x40, m) // Restore the free memory pointer.
        }
        bool success = _isValidSignature(_hashTypedData(hash), signature);
        /// @solidity memory-safe-assembly
        assembly {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    /// @dev Must override to provide the signature verification logic.
    /// For the nested EIP-712 workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 || DOMAIN_SEP_A ||
    ///         hashStruct(Parent({
    ///             childHash: keccak256(\x19\x01 || DOMAIN_SEP_B || hashStruct(originalStruct)),
    ///             child: hashStruct(originalStruct)
    ///         }))
    ///     )
    /// ```
    ///
    /// For the `personal_sign` workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 || DOMAIN_SEP_A ||
    ///         hashStruct(Parent({
    ///             childHash: personalSign(someBytes)
    ///         }))
    ///     )
    /// ```
    /// @param derivedHash The final hash that is derived from the original hash and signature passed to
    /// `isValidSignature`.
    /// @param trimmedSignature The actual signature component of the signature passed to `isValidSignature`.
    /// @return Whether the signature is valid.
    function _isValidSignature(bytes32 derivedHash, bytes calldata trimmedSignature)
        internal
        view
        virtual
        returns (bool);
}
