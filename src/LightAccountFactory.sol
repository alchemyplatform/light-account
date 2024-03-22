// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {BaseLightAccountFactory} from "./common/BaseLightAccountFactory.sol";
import {LibClone} from "./external/solady/LibClone.sol";
import {LightAccount} from "./LightAccount.sol";

/// @title A factory contract for LightAccount.
/// @dev A UserOperations "initCode" holds the address of the factory, and a method call (`createAccount`). The
/// factory's `createAccount` returns the target account address even if it is already installed. This way,
/// `entryPoint.getSenderAddress()` can be called either before or after the account is created.
contract LightAccountFactory is BaseLightAccountFactory {
    LightAccount public immutable ACCOUNT_IMPLEMENTATION;

    constructor(address owner, IEntryPoint entryPoint) Ownable(owner) {
        ACCOUNT_IMPLEMENTATION = new LightAccount(entryPoint);
        ENTRY_POINT = entryPoint;
    }

    /// @notice Create an account, and return its address. Returns the address even if the account is already deployed.
    /// @dev During UserOperation execution, this method is called only if the account is not deployed. This method
    /// returns an existing account address so that entryPoint.getSenderAddress() would work even after account
    /// creation.
    /// @param owner The owner of the account to be created.
    /// @param salt A salt, which can be changed to create multiple accounts with the same owner.
    /// @return account The address of either the newly deployed account or an existing account with this owner and salt.
    function createAccount(address owner, uint256 salt) public returns (LightAccount account) {
        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(address(ACCOUNT_IMPLEMENTATION), _getCombinedSalt(owner, salt));

        account = LightAccount(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(owner);
        }
    }

    /// @notice Calculate the counterfactual address of this account as it would be returned by `createAccount`.
    /// @param owner The owner of the account to be created.
    /// @param salt A salt, which can be changed to create multiple accounts with the same owner.
    /// @return The address of the account that would be created with `createAccount`.
    function getAddress(address owner, uint256 salt) public view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(
            address(ACCOUNT_IMPLEMENTATION), _getCombinedSalt(owner, salt), address(this)
        );
    }

    /// @notice Compute the hash of the owner and salt in scratch space memory.
    /// @param owner The owner of the account to be created.
    /// @param salt A salt, which can be changed to create multiple accounts with the same owner.
    /// @return combinedSalt The hash of the owner and salt.
    function _getCombinedSalt(address owner, uint256 salt) internal pure returns (bytes32 combinedSalt) {
        // Compute the hash of the owner and salt in scratch space memory.
        assembly ("memory-safe") {
            mstore(0x00, owner)
            mstore(0x20, salt)
            combinedSalt := keccak256(0x00, 0x40)
        }
    }
}
