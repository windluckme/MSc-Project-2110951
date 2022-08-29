// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

contract Hash_SC{
    function hash(string memory cert) public pure returns(bytes32){
        return keccak256(abi.encodePacked(cert));
    }
}


