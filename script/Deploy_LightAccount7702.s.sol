// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccount7702} from "../src/LightAccount7702.sol";

contract Deploy_LightAccount7702 is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load deploy inputs from env
    bytes32 public implSalt = vm.envBytes32("IMPL_SALT");
    address public expectedImplAddress = vm.envAddress("EXPECTED_IMPL_ADDRESS");

    error DeployedAddressMismatch(address deployed);

    function run() public {
        vm.startBroadcast();

        console.log("********************************");
        console.log("******** Deploy Inputs *********");
        console.log("********************************");
        console.log("Entrypoint:", address(entryPoint));
        console.log("Impl salt:", vm.toString(implSalt));
        console.log();
        console.log("********************************");
        console.log("******** Deploying.... *********");
        console.log("********************************");

        LightAccount7702 impl = new LightAccount7702{salt: implSalt}(entryPoint);

        // Deployed address check
        if (address(impl) != expectedImplAddress) {
            revert DeployedAddressMismatch(address(impl));
        }

        console.log("LightAccount7702:", address(impl));
        console.log();

        vm.stopBroadcast();
    }
}
