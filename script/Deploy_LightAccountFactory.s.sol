// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "../src/LightAccountFactory.sol";

// @notice Deploys LightAccountFactory to the address `[TODO]`
// @dev Note: Script uses EntryPoint at address 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
// @dev To run: `forge script script/Deploy_LightAccountFactory.s.sol:Deploy_LightAccountFactory --broadcast --rpc-url ${RPC_URL} --verify -vvvv`
contract Deploy_LightAccountFactory is Script {
    error InitCodeHashMismatch(bytes32 initCodeHash);
    error DeployedAddressMismatch(address deployed);

    function run() public {
        vm.startBroadcast();

        // Using entryPoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
        // Correct as of Dec 23 2023, from https://docs.alchemy.com/reference/eth-supportedentrypoints
        IEntryPoint entryPoint = IEntryPoint(payable(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789));

        // Init code hash check
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(type(LightAccountFactory).creationCode, bytes32(uint256(uint160(address(entryPoint)))))
        );

        if (initCodeHash != 0x72db05fba86adbc64040d8949a885cd2a59aa1604d3c84bec19870bd9a7db0d5) {
            revert InitCodeHashMismatch(initCodeHash);
        }

        console.log("********************************");
        console.log("******** Deploy Inputs *********");
        console.log("********************************");
        console.log("Entrypoint Address is:");
        console.logAddress(address(entryPoint));
        console.log("********************************");
        console.log("******** Deploy ...... *********");
        console.log("********************************");

        LightAccountFactory factory = new LightAccountFactory{
            salt: 0x4e59b44847b379578588920ca78fbf26c0b4956cce883a81e259e4000035f09a
        }(entryPoint);

        // Deployed address check
        if (address(factory) != 0x00000010A100a25D176503d5c50C4ae0dF2d5120) {
            revert DeployedAddressMismatch(address(factory));
        }

        console.log("LightAccountFactory address:");
        console.logAddress(address(factory));

        console.log("Implementation address:");
        console.logAddress(address(factory.accountImplementation()));
        vm.stopBroadcast();
    }
}
