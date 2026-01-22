// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {MultiOwnerLightAccountFactory} from "../src/MultiOwnerLightAccountFactory.sol";

contract Deploy_MultiOwnerLightAccountFactory is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load factory owner from env
    address public owner = vm.envAddress("OWNER");

    error InitCodeHashMismatch(bytes32 initCodeHash);
    error DeployedAddressMismatch(address deployed);

    function run() public {
        vm.startBroadcast();

        // read initcode from file
        string memory hexInitCode = vm.readFile("bytecode/mola-creationcode.bin");
        bytes memory initcode = vm.parseBytes(hexInitCode);

        bytes32 initCodeHash = keccak256(initcode);

        if (initCodeHash != 0x69e0f4a2942425638860e9982bd32f08941a082681e53208de970099f18252cc) {
            revert InitCodeHashMismatch(initCodeHash);
        }

        // ensure the env vars are the expected values for the bytecode
        require(
            entryPointAddr == 0x0000000071727De22E5E9d8BAf0edAc6f37da032,
            "Entrypoint address is not correct for deployment"
        );
        require(owner == 0xDdF32240B4ca3184De7EC8f0D5Aba27dEc8B7A5C, "Owner address is not correct for deployment");

        console.log("********************************");
        console.log("******** Deploy Inputs *********");
        console.log("********************************");
        console.log("Owner:", owner);
        console.log("Entrypoint:", address(entryPoint));
        console.log();
        console.log("********************************");
        console.log("******** Deploying.... *********");
        console.log("********************************");

        MultiOwnerLightAccountFactory factory = deployImpl(
            0x0000000000000000000000000000000000000000bb3ab048b3f4ef2620ea0163,
            0x000000000019d2Ee9F2729A65AfE20bb0020AefC,
            initcode
        );

        _addStakeForFactory(address(factory));

        console.log("MultiOwnerLightAccountFactory:", address(factory));
        console.log("MultiOwnerLightAccount:", address(factory.ACCOUNT_IMPLEMENTATION()));
        console.log();

        vm.stopBroadcast();
    }

    function deployImpl(bytes32 saltBytes, address expected, bytes memory initcode)
        private
        returns (MultiOwnerLightAccountFactory)
    {
        address addr = Create2.computeAddress(saltBytes, keccak256(initcode), CREATE2_FACTORY);
        console.logAddress(addr);
        require(addr == expected, "Expected address is not the same as computed for impl");
        if (addr.code.length > 0) {
            console.log("MultiOwnerLightAccount impl already deployed. Skipping");
            return MultiOwnerLightAccountFactory(payable(addr));
        }

        address impl = Create2.deploy(0, saltBytes, initcode);
        require(impl == addr, "Impl address did not match predicted");
        return MultiOwnerLightAccountFactory(payable(impl));
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
            console.log("******** Stake Verify Done *********");
        } else {
            console.log("No stake needed for factory");
        }
    }
}
