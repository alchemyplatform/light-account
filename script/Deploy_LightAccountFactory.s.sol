// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "../src/LightAccountFactory.sol";

contract Deploy_LightAccountFactory is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load factory owner from env
    address public owner = vm.envAddress("OWNER");

    error InitCodeHashMismatch(bytes32 initCodeHash);
    error DeployedAddressMismatch(address deployed);

    function run() public {
        vm.startBroadcast();

        // Init code hash check
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(LightAccountFactory).creationCode, abi.encode(owner, entryPoint)));

        if (initCodeHash != 0xfad339962af095db6ac3163c8504f102c28ae099db994101fbbca18ad0e3005c) {
            revert InitCodeHashMismatch(initCodeHash);
        }

        console.log("********************************");
        console.log("******** Deploy Inputs *********");
        console.log("********************************");
        console.log("Owner:", owner);
        console.log("Entrypoint:", address(entryPoint));
        console.log();
        console.log("********************************");
        console.log("******** Deploying.... *********");
        console.log("********************************");

        LightAccountFactory factory = new LightAccountFactory{
            salt: 0x00000000000000000000000000000000000000005f1ffd9d31306e056bcc959b
        }(owner, entryPoint);

        // Deployed address check
        if (address(factory) != 0x0000000000400CdFef5E2714E63d8040b700BC24) {
            revert DeployedAddressMismatch(address(factory));
        }

        _addStakeForFactory(address(factory));

        console.log("LightAccountFactory:", address(factory));
        console.log("LightAccount:", address(factory.ACCOUNT_IMPLEMENTATION()));
        console.log();

        vm.stopBroadcast();
    }

    function _addStakeForFactory(address factoryAddr) internal {
        uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(86400)));
        uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT");
        uint256 currentStakedAmount = entryPoint.getDepositInfo(factoryAddr).stake;
        uint256 stakeAmount = requiredStakeAmount - currentStakedAmount;
        LightAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount}(unstakeDelaySec, stakeAmount);
        console.log("******** Add Stake Verify *********");
        console.log("Staked factory: ", factoryAddr);
        console.log("Stake amount: ", entryPoint.getDepositInfo(factoryAddr).stake);
        console.log("Unstake delay: ", entryPoint.getDepositInfo(factoryAddr).unstakeDelaySec);
        console.log("******** Stake Verify Done *********");
    }
}
