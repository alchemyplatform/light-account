// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "../src/LightAccountFactory.sol";

// @notice Deploys LightAccountFactory to the address `0x00000055C0b4fA41dde26A74435ff03692292FBD`
// @dev Note: Script uses EntryPoint at address 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
// @dev To run: `forge script script/Deploy_LightAccountFactory.s.sol:Deploy_LightAccountFactory --broadcast --rpc-url ${RPC_URL} --verify -vvvv`
contract Deploy_LightAccountFactory is Script {
    error InitCodeHashMismatch(bytes32 initCodeHash);
    error DeployedAddressMismatch(address deployed);

    function run() public {
        vm.startBroadcast();

        // Using entryPoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
        // Correct as of Oct 3 2023, from https://docs.alchemy.com/reference/eth-supportedentrypoints
        IEntryPoint entryPoint = IEntryPoint(payable(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789));

        // Init code hash check
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(type(LightAccountFactory).creationCode, bytes32(uint256(uint160(address(entryPoint)))))
        );

        if (initCodeHash != 0x2ad62a8bb3850247ef0c4f04e30b584e6eee7caa0e063745e90956653b90eb84) {
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

        LightAccountFactory factory =
        new LightAccountFactory{salt: 0x4e59b44847b379578588920ca78fbf26c0b4956c3406f3bdc271500000c2f72f}(entryPoint);

        // Deployed address check
        if (address(factory) != 0x00000055C0b4fA41dde26A74435ff03692292FBD) {
            revert DeployedAddressMismatch(address(factory));
        }

        console.log("LightAccountFactory address:");
        console.logAddress(address(factory));

        console.log("Implementation address:");
        console.logAddress(address(factory.accountImplementation()));
        vm.stopBroadcast();
    }
}
