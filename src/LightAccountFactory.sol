// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.21;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccount} from "./LightAccount.sol";

/**
 * @title A factory contract for LightAccount
 * @dev A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract LightAccountFactory {
    LightAccount public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new LightAccount(_entryPoint);
    }

    /**
     * @notice Create an account, and return its address.
     * Returns the address even if the account is already deployed.
     * @dev During UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation.
     * @param owner The owner of the account to be created
     * @param salt A salt, which can be changed to create multiple accounts with the same owner
     * @return ret The address of either the newly deployed account or an existing account with this owner and salt
     */
    function createAccount(address owner, uint256 salt) public returns (LightAccount ret) {
        address addr = getAddress(owner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return LightAccount(payable(addr));
        }
        ret = LightAccount(
            payable(
                new ERC1967Proxy{salt : bytes32(salt)}(
                    address(accountImplementation),
                    abi.encodeCall(LightAccount.initialize, (owner))
                )
            )
        );
    }

    /**
     * @notice Calculate the counterfactual address of this account as it would be returned by createAccount()
     * @param owner The owner of the account to be created
     * @param salt A salt, which can be changed to create multiple accounts with the same owner
     * @return The address of the account that would be created with createAccount()
     */
    function getAddress(address owner, uint256 salt) public view returns (address) {
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(address(accountImplementation), abi.encodeCall(LightAccount.initialize, (owner)))
                )
            )
        );
    }
}
