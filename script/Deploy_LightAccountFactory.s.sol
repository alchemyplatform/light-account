// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "../src/LightAccountFactory.sol";

// @notice Deploys LightAccountFactory to the address `0x000000893A26168158fbeaDD9335Be5bC96592E2`
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

        // if (initCodeHash != 0x3043a72812fec9b9987853a9b869c1a469dc6e04b0f80da3af2ecb8cf8eed209) {
        //     revert InitCodeHashMismatch(initCodeHash);
        // }

        console.log("********************************");
        console.log("******** Deploy Inputs *********");
        console.log("********************************");
        console.log("Entrypoint Address is:");
        console.logAddress(address(entryPoint));
        console.log("********************************");
        console.log("******** Deploy ...... *********");
        console.log("********************************");

        LightAccountFactory factory =
        new LightAccountFactory{salt: 0x00000000000000000000000000000000000000007845d3459c316000001d6f83}(entryPoint);

        // Deployed address check
        // if (address(factory) != 0x000000893A26168158fbeaDD9335Be5bC96592E2) {
        //     revert DeployedAddressMismatch(address(factory));
        // }

        console.log("LightAccountFactory address:");
        console.logAddress(address(factory));

        console.log("Implementation address:");
        console.logAddress(address(factory.accountImplementation()));
        vm.stopBroadcast();
    }
}
