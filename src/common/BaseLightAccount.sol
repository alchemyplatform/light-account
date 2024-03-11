// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";

import {UUPSUpgradeable} from "../../ext/solady/UUPSUpgradeable.sol";

abstract contract BaseLightAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, IERC1271 {
    bytes4 internal constant _1271_MAGIC_VALUE = bytes4(keccak256("isValidSignature(bytes32,bytes)")); // 0x1626ba7e
    IEntryPoint internal immutable _ENTRY_POINT;

    /// @dev The length of the array does not match the expected length.
    error ArrayLengthMismatch();

    /// @dev The caller is not authorized.
    error NotAuthorized(address caller);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable virtual {}

    /// @notice Execute a transaction. This may only be called directly by an owner or by the entry point via a user
    /// operation signed by an owner.
    /// @param dest The target of the transaction.
    /// @param value The amount of wei sent in the transaction.
    /// @param func The transaction's calldata.
    function execute(address dest, uint256 value, bytes calldata func) external virtual {
        _onlyOwnerOrEntryPoint();
        _call(dest, value, func);
    }

    /// @notice Execute a sequence of transactions.
    /// @param dest An array of the targets for each transaction in the sequence.
    /// @param func An array of calldata for each transaction in the sequence. Must be the same length as `dest`, with
    /// corresponding elements representing the parameters for each transaction.
    function executeBatch(address[] calldata dest, bytes[] calldata func) external virtual {
        _onlyOwnerOrEntryPoint();
        if (dest.length != func.length) {
            revert ArrayLengthMismatch();
        }
        uint256 length = dest.length;
        for (uint256 i = 0; i < length; ++i) {
            _call(dest[i], 0, func[i]);
        }
    }

    /// @notice Execute a sequence of transactions.
    /// @param dest An array of the targets for each transaction in the sequence.
    /// @param value An array of value for each transaction in the sequence.
    /// @param func An array of calldata for each transaction in the sequence. Must be the same length as `dest`, with
    /// corresponding elements representing the parameters for each transaction.
    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func) external virtual {
        _onlyOwnerOrEntryPoint();
        if (dest.length != func.length || dest.length != value.length) {
            revert ArrayLengthMismatch();
        }
        uint256 length = dest.length;
        for (uint256 i = 0; i < length; ++i) {
            _call(dest[i], value[i], func[i]);
        }
    }

    /// @notice Deposit more funds for this account in the entry point.
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraw value from the account's deposit.
    /// @param withdrawAddress Target to send to.
    /// @param amount Amount to withdraw.
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _ENTRY_POINT;
    }

    /// @notice Check current account deposit in the entry point.
    /// @return The current account deposit.
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /// @inheritdoc IERC1271
    /// @dev Must override to support ERC-1271 signature validation.
    function isValidSignature(bytes32 hash, bytes memory signature) public view virtual override returns (bytes4);

    /// @dev Must override to allow calls to protected functions.
    function _isFromOwner() internal view virtual returns (bool);

    function _isFromEntryPoint() internal view returns (bool) {
        return msg.sender == address(entryPoint());
    }

    /// @dev Revert if the caller is not an owner or the account itself (when redirected through `execute`).
    function _onlyOwner() internal view {
        if (msg.sender != address(this) && !_isFromOwner()) {
            revert NotAuthorized(msg.sender);
        }
    }

    /// @dev Require that the call is from the entry point or an owner.
    function _onlyOwnerOrEntryPoint() internal view {
        if (!_isFromEntryPoint() && !_isFromOwner()) {
            revert NotAuthorized(msg.sender);
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }
}
