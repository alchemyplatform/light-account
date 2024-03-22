// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

abstract contract BaseLightAccountFactory is Ownable2Step {
    IEntryPoint public immutable ENTRY_POINT;

    error InvalidAction();
    error TransferFailed();

    /// @notice Allow contract to receive native currency.
    receive() external payable {}

    /// @notice Add stake to an entry point.
    /// @dev Only callable by owner.
    /// @param unstakeDelay Unstake delay for the stake.
    /// @param amount Amount of native currency to stake.
    function addStake(uint32 unstakeDelay, uint256 amount) external payable onlyOwner {
        ENTRY_POINT.addStake{value: amount}(unstakeDelay);
    }

    /// @notice Start unlocking stake for an entry point.
    /// @dev Only callable by owner.
    function unlockStake() external onlyOwner {
        ENTRY_POINT.unlockStake();
    }

    /// @notice Withdraw stake from an entry point.
    /// @dev Only callable by owner.
    /// @param to Address to send native currency to.
    function withdrawStake(address payable to) external onlyOwner {
        ENTRY_POINT.withdrawStake(to);
    }

    /// @notice Withdraw funds from this contract.
    /// @dev Can withdraw stuck erc20s or native currency.
    /// @param to Address to send erc20s or native currency to.
    /// @param token Address of the token to withdraw, 0 address for native currency.
    /// @param amount Amount of the token to withdraw in case of rebasing tokens.
    function withdraw(address payable to, address token, uint256 amount) external onlyOwner {
        if (token == address(0)) {
            (bool success,) = to.call{value: address(this).balance}("");
            if (!success) {
                revert TransferFailed();
            }
        } else {
            SafeERC20.safeTransfer(IERC20(token), to, amount);
        }
    }

    /// @notice Overriding to disable renounce ownership in Ownable.
    function renounceOwnership() public view override onlyOwner {
        revert InvalidAction();
    }
}
