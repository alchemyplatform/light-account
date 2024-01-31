// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {SimpleAccount} from "account-abstraction/samples/SimpleAccount.sol";

import {LightAccount} from "../src/LightAccount.sol";
import {LightAccountFactory} from "../src/LightAccountFactory.sol";

contract ExampleNFT is ERC721, Ownable {
    constructor(address owner) ERC721("ExampleNFT", "ENFT") {
        transferOwnership(owner);
    }

    function safeMint(address to, uint256 tokenId) public onlyOwner {
        _safeMint(to, tokenId);
    }
}

contract SafeMintTest is Test {
    EntryPoint internal _entryPoint;
    address payable internal _beneficiary;

    uint256 internal _owner1PrivateKey;
    address internal _owner1;

    LightAccount internal _account1;
    LightAccountFactory internal _factory;

    ExampleNFT internal _nft;

    function setUp() public {
        _entryPoint = new EntryPoint();
        _factory = new LightAccountFactory(_entryPoint);

        _beneficiary = payable(makeAddr("beneficiary"));

        (_owner1, _owner1PrivateKey) = makeAddrAndKey("owner1");

        _account1 = _factory.createAccount(_owner1, 0);

        vm.deal(address(_account1), 100 ether);

        _nft = new ExampleNFT(address(this));
    }

    function test_safeMint() public {
        _nft.safeMint(address(_account1), 1);
        assertEq(_nft.ownerOf(1), address(_account1));
    }
}
