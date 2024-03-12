// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {MultiOwnerLightAccount} from "./MultiOwnerLightAccount.sol";

/// @title A factory contract for MultiOwnerLightAccount.
/// @dev A UserOperations "initCode" holds the address of the factory, and a method call (`createAccount` or
/// `createAccountSingle`). The factory returns the target account address even if it is already deployed. This way,
/// `entryPoint.getSenderAddress()` can be called either before or after the account is created.
contract MultiOwnerLightAccountFactory {
    uint256 internal constant _MAX_OWNERS_ON_CREATION = 100;
    MultiOwnerLightAccount public immutable accountImplementation;

    error InvalidOwners();
    error OwnersArrayEmpty();
    error OwnersLimitExceeded();

    constructor(IEntryPoint entryPoint) {
        accountImplementation = new MultiOwnerLightAccount(entryPoint);
    }

    /// @notice Create an account, and return its address. Returns the address even if the account is already deployed.
    /// @dev During UserOperation execution, this method is called only if the account is not deployed. This method
    /// returns an existing account address so that `entryPoint.getSenderAddress()` would work even after account
    /// creation.
    /// @param owners The owners of the account to be created.
    /// @param salt A salt, which can be changed to create multiple accounts with the same owners.
    /// @return ret The address of either the newly deployed account or an existing account with these owners and salt.
    function createAccount(address[] calldata owners, uint256 salt) public returns (MultiOwnerLightAccount ret) {
        address addr = getAddress(owners, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return MultiOwnerLightAccount(payable(addr));
        }
        ret = MultiOwnerLightAccount(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(accountImplementation), abi.encodeCall(MultiOwnerLightAccount.initialize, (owners))
                )
            )
        );
    }

    /// @notice Create an account, and return its address. Returns the address even if the account is already deployed.
    /// @dev This method uses less calldata than `createAccount` when creating accounts with a single initial owner.
    /// @param owner The owner of the account to be created.
    /// @param salt A salt, which can be changed to create multiple accounts with the same owner.
    /// @return ret The address of either the newly deployed account or an existing account with this owner and salt.
    function createAccountSingle(address owner, uint256 salt) public returns (MultiOwnerLightAccount ret) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        address addr = getAddress(owners, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return MultiOwnerLightAccount(payable(addr));
        }
        ret = MultiOwnerLightAccount(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(accountImplementation), abi.encodeCall(MultiOwnerLightAccount.initialize, (owners))
                )
            )
        );
    }

    /// @notice Calculate the counterfactual address of this account as it would be returned by `createAccount`.
    /// @param owners The owners of the account to be created.
    /// @param salt A salt, which can be changed to create multiple accounts with the same owners.
    /// @return The address of the account that would be created with `createAccount`.
    function getAddress(address[] memory owners, uint256 salt) public view returns (address) {
        _validateOwnersArray(owners);

        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(
                        address(accountImplementation), abi.encodeCall(MultiOwnerLightAccount.initialize, (owners))
                    )
                )
            )
        );
    }

    /// @dev `owners` must be in strictly ascending order and not include the 0 address. The ordering requirement
    /// ensures a canonical counterfactual for a given set of initial owners. Also, its length must not be empty
    /// and not exceed `_MAX_OWNERS_ON_CREATION`.
    /// @param owners Array of owner addresses.
    function _validateOwnersArray(address[] memory owners) internal pure {
        if (owners.length == 0) {
            revert OwnersArrayEmpty();
        }

        // This protects against counterfactuals being generated against an exceptionally large number of owners
        // that may exceed the block gas limit when actually creating the account.
        if (owners.length > _MAX_OWNERS_ON_CREATION) {
            revert OwnersLimitExceeded();
        }

        address prevOwner;
        uint256 length = owners.length;
        for (uint256 i = 0; i < length; ++i) {
            if (owners[i] <= prevOwner) {
                revert InvalidOwners();
            }
            prevOwner = owners[i];
        }
    }
}
