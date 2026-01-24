// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LightAccountFactory} from "../src/LightAccountFactory.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract Deploy_LightAccountFactory is Script {
    using stdJson for string;

    IEntryPoint entryPoint;
    address entryPointAddr;
    address expectedAddress;
    address owner;
    uint256 salt;
    uint256 stakeAmount;
    uint256 unstakeDelay;

    error InitCodeHashMismatch(bytes32 initCodeHash);
    error DeployedAddressMismatch(address deployed);

    function readInputsFromPath() internal {
        string memory json = vm.readFile("input.json");
        entryPointAddr = json.readAddress("$.entryPoint");
        entryPoint = IEntryPoint(payable(entryPointAddr));
        expectedAddress = json.readAddress("$.address");
        owner = json.readAddress("$.owner");
        salt = json.readUint("$.salt");
        stakeAmount = json.readUint("$.stakeAmount");
        unstakeDelay = json.readUint("$.unstakeDelay");
    }


    function run() public {
        readInputsFromPath();
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

        // read initcode from file
        string memory hexInitCode = vm.readFile("bytecode/creationcode.bin");
        bytes memory initcode = vm.parseBytes(hexInitCode);

        // ensure the env vars are the expected values for the bytecode
        require(salt == 0x00000000000000000000000000000000000000005f1ffd9d31306e056bcc959b, "Salt is not correct for deployment");
        require(entryPointAddr == 0x0000000071727De22E5E9d8BAf0edAc6f37da032, "Entrypoint address is not correct for deployment");
        require(owner == 0xDdF32240B4ca3184De7EC8f0D5Aba27dEc8B7A5C, "Owner address is not correct for deployment");

        LightAccountFactory factory = deployImpl(initcode, bytes32(salt), expectedAddress);

        _addStakeForFactory(address(factory));
        console.log("LightAccountFactory:", address(factory));
        console.log("LightAccount:", address(factory.ACCOUNT_IMPLEMENTATION()));
        console.log();

        vm.stopBroadcast();
    }


    function deployImpl(bytes memory initcode, bytes32 saltBytes, address expected) private returns (LightAccountFactory) {
        address addr = Create2.computeAddress(
            saltBytes, keccak256(initcode), CREATE2_FACTORY
        );
        console.logAddress(addr);
        require(addr == expected, "Expected address is not the same as computed for impl");
        if (addr.code.length > 0) {
            console.log("VerifyingPaymaster impl already deployed. Skipping");
            return LightAccountFactory(payable(addr));
        }

        address impl = Create2.deploy(0, saltBytes, initcode);
        LightAccountFactory factory = LightAccountFactory(payable(impl));
        require(address(factory) == addr, "Impl address did not match predicted");
        return factory;
    }


    function _addStakeForFactory(address factoryAddr) internal {
        uint256 currentStakedAmount = entryPoint.getDepositInfo(factoryAddr).stake;

        if (currentStakedAmount >= stakeAmount) {
            console.log("Contract already sufficient staked");
            return;
        }

        LightAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount - currentStakedAmount}(uint32(unstakeDelay), stakeAmount - currentStakedAmount);
        console.log("******** Add Stake Verify *********");
        console.log("Staked factory: ", factoryAddr);
        console.log("Stake amount: ", entryPoint.getDepositInfo(factoryAddr).stake);
        console.log("Unstake delay: ", entryPoint.getDepositInfo(factoryAddr).unstakeDelaySec);
        console.log("******** Stake Verify Done *********");
    }
}
