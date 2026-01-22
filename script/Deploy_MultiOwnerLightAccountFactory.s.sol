// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {MultiOwnerLightAccountFactory} from "../src/MultiOwnerLightAccountFactory.sol";

contract Deploy_MultiOwnerLightAccountFactory is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load factory inputs from env
    address public owner = vm.envAddress("OWNER");
    address public expectedFactoryAddress = vm.envAddress("EXPECTED_FACTORY_ADDRESS");
    bytes32 public factorySalt = vm.envBytes32("FACTORY_SALT");

    error DeployedAddressMismatch(address deployed);

    function run() public {
        vm.startBroadcast();

        console.log("********************************");
        console.log("******** Deploy Inputs *********");
        console.log("********************************");
        console.log("Owner:", owner);
        console.log("Entrypoint:", address(entryPoint));
        console.log();
        console.log("********************************");
        console.log("******** Deploying.... *********");
        console.log("********************************");

        MultiOwnerLightAccountFactory factory = new MultiOwnerLightAccountFactory{salt: factorySalt}(owner, entryPoint);

        // Deployed address check
        if (address(factory) != expectedFactoryAddress) {
            revert DeployedAddressMismatch(address(factory));
        }

        _addStakeForFactory(address(factory));

        console.log("MultiOwnerLightAccountFactory:", address(factory));
        console.log("MultiOwnerLightAccount:", address(factory.ACCOUNT_IMPLEMENTATION()));
        console.log();

        vm.stopBroadcast();
    }

    function _addStakeForFactory(address factoryAddr) internal {
        uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(86400)));
        uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT");
        uint256 currentStakedAmount = entryPoint.getDepositInfo(factoryAddr).stake;
        uint256 stakeAmount = requiredStakeAmount - currentStakedAmount;

        if (stakeAmount > 0) {
            MultiOwnerLightAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount}(
                unstakeDelaySec, stakeAmount
            );
            console.log("******** Add Stake Verify *********");
            console.log("Staked factory: ", factoryAddr);
            console.log("Stake amount: ", entryPoint.getDepositInfo(factoryAddr).stake);
            console.log("Unstake delay: ", entryPoint.getDepositInfo(factoryAddr).unstakeDelaySec);
            console.log("******** Stake Verify Done! *********");
        } else {
            console.log("No stake needed for factory");
        }
    }
}
