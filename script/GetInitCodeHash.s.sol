// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/Test.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "../src/LightAccountFactory.sol";
import {MultiOwnerLightAccountFactory} from "../src/MultiOwnerLightAccountFactory.sol";

contract GetInitCodeHash is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load factory owner from env
    address public owner = vm.envAddress("OWNER");

    function run() public view {
        console.log("******** Calculating Init Code Hashes *********");
        console.log("Chain: ", block.chainid);
        console.log("EP: ", entryPointAddr);
        console.log("Factory owner: ", owner);

        bytes memory lightAccountFactoryInitCode =
            abi.encodePacked(type(LightAccountFactory).creationCode, abi.encode(owner, entryPoint));

        bytes32 lightAccountFactoryInitCodeHash = keccak256(lightAccountFactoryInitCode);

        console.log("LightAccountFactory init code hash:");
        console.logBytes32(lightAccountFactoryInitCodeHash);

        bytes memory multiOwnerLightAccountFactoryInitCode =
            abi.encodePacked(type(MultiOwnerLightAccountFactory).creationCode, abi.encode(owner, entryPoint));

        bytes32 multiOwnerLightAccountFactoryInitCodeHash = keccak256(multiOwnerLightAccountFactoryInitCode);

        console.log("MultiOwnerLightAccountFactory init code hash:");
        console.logBytes32(multiOwnerLightAccountFactoryInitCodeHash);
    }
}
