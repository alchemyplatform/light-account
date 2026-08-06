// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "../src/LightAccountFactory.sol";

contract Deploy_LightAccountFactory is Script {
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

        if (expectedFactoryAddress.code.length == 0) {
            address factory = address(new LightAccountFactory{salt: factorySalt}(owner, entryPoint));
            // Deployed address check
            if (factory != expectedFactoryAddress) {
                revert DeployedAddressMismatch(factory);
            }
        } else {
            console.log("Factory already deployed at: ", expectedFactoryAddress);
        }

        _addStakeForFactory(expectedFactoryAddress);

        console.log("LightAccountFactory:", address(expectedFactoryAddress));
        console.log(
            "LightAccount:", address(LightAccountFactory(payable(expectedFactoryAddress)).ACCOUNT_IMPLEMENTATION())
        );
        console.log();

        vm.stopBroadcast();
    }

    function _addStakeForFactory(address factoryAddr) internal {
        uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(86400)));
        uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT");
        uint256 currentStakedAmount = entryPoint.getDepositInfo(factoryAddr).stake;
        // Clamp rather than subtract directly: a factory staked above the required amount underflows, and
        // the deployer passes a required amount of 0 when staking is meant to be skipped entirely.
        uint256 stakeAmount = requiredStakeAmount > currentStakedAmount ? requiredStakeAmount - currentStakedAmount : 0;

        if (stakeAmount > 0) {
            LightAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount}(unstakeDelaySec, stakeAmount);
            console.log("******** Add Stake Verify *********");
            console.log("Staked factory: ", factoryAddr);
            console.log("Stake amount: ", entryPoint.getDepositInfo(factoryAddr).stake);
            console.log("Unstake delay: ", entryPoint.getDepositInfo(factoryAddr).unstakeDelaySec);
            console.log("******** Stake Verify Done *********");
        } else {
            console.log("Factory already staked");
        }
    }
}
